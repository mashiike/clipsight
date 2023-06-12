package clipsight

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	gv "github.com/hashicorp/go-version"
	"go.mozilla.org/sops/v3/decrypt"
	"golang.org/x/exp/slog"
	"gopkg.in/yaml.v3"
)

type VersionConstraint struct {
	gv.Constraints
}

func (c *VersionConstraint) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	constraints, err := gv.NewConstraint(s)
	if err != nil {
		return err
	}
	c.Constraints = constraints
	return nil
}

func (c *VersionConstraint) Check(v string) bool {
	if c.Constraints == nil {
		return true
	}
	version, err := gv.NewVersion(v)
	if err != nil {
		slog.Warn("version is not semver", slog.String("version", v))
		return true
	}
	return c.Constraints.Check(version)
}

type sopsConfig struct {
	Sops interface{} `yaml:"sops,omitempty"`
}

func (c *sopsConfig) IsEncrypted() bool {
	return c.Sops != nil
}

type Config struct {
	RequiredVersion VersionConstraint `yaml:"required_version"`
	Users           []*User           `yaml:"users"`
}

func (c *Config) Merge(other *Config) {
	if other == nil {
		return
	}
	if other.RequiredVersion.Constraints != nil {
		if c.RequiredVersion.Constraints == nil {
			c.RequiredVersion.Constraints = other.RequiredVersion.Constraints
		} else {
			// merge constraints
			for i := 0; i < len(other.RequiredVersion.Constraints); i++ {
				var found bool
				otherConstraint := other.RequiredVersion.Constraints[i]
				for j := 0; j < len(c.RequiredVersion.Constraints); j++ {
					currentConstraint := c.RequiredVersion.Constraints[j]
					if otherConstraint.Equals(currentConstraint) {
						found = true
						break
					}
				}
				if !found {
					c.RequiredVersion.Constraints = append(c.RequiredVersion.Constraints, otherConstraint)
				}
			}
		}
	}
	c.Users = append(c.Users, other.Users...)
}

func (c *Config) Validate() error {
	if !c.RequiredVersion.Check(Version) {
		return fmt.Errorf("version %s is not satisfied", Version)
	}
	users := map[string]struct{}{}
	for _, user := range c.Users {
		if _, ok := users[user.Email.String()]; ok {
			return fmt.Errorf("duplicate user %s", user.Email)
		}
	}
	return nil
}

func LoadConfig(p string) (*Config, error) {
	stat, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !stat.IsDir() {
		return loadConfigFile(p)
	}
	entities, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	var config Config
	for _, entity := range entities {
		if entity.IsDir() {
			slog.Debug("skip directory", slog.String("entity_name", entity.Name()))
			continue
		}
		if filepath.Ext(entity.Name()) != ".yaml" {
			slog.Debug("skip non-yaml file", slog.String("entity_name", entity.Name()))
			continue
		}
		c, err := loadConfigFile(filepath.Join(p, entity.Name()))
		if err != nil {
			return nil, fmt.Errorf("load config file %s: %w", entity.Name(), err)
		}
		config.Merge(c)
	}
	return &config, config.Validate()
}

func loadConfigFile(p string) (*Config, error) {
	bs, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var sopsConfig sopsConfig
	decoder := yaml.NewDecoder(bytes.NewReader(bs))
	if err := decoder.Decode(&sopsConfig); err != nil {
		return nil, err
	}
	if sopsConfig.IsEncrypted() {
		bs, err = decrypt.Data(bs, "yaml")
		if err != nil {
			return nil, err
		}
	}
	tpl, err := template.New("permission_file").Funcs(template.FuncMap{
		"must_env": func(key string) (string, error) {
			if v, ok := os.LookupEnv(key); ok {
				return v, nil
			}
			return "", fmt.Errorf("environment variable %s is not defined", key)
		},
		"env": func(key string) string {
			return os.Getenv(key)
		},
	}).Parse(string(bs))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, nil); err != nil {
		return nil, err
	}
	var config Config
	decoder = yaml.NewDecoder(&buf)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	for i, u := range config.Users {
		if err := u.Restrict(); err != nil {
			return nil, fmt.Errorf("user[%d]: %w", i, err)
		}
	}
	return &config, nil
}
