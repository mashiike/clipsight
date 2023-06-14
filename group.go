package clipsight

type Group struct {
	schema
	ID         string       `dynamodb:"ID" yaml:"id" json:"id"`
	Namespace  string       `dynamodb:"Namespace" yaml:"namespace" json:"namespace"`
	Dashboards []*Dashboard `dynamodb:"Dashboards" yaml:"dashboards" json:"dashboards"`
}

func (g *Group) FillKey() *Group {
	g.HashKey = "GROUP"
	g.SortKey = "GROUP:" + g.ID
	return g
}

func (g *Group) IsNew() bool {
	return g.Revision == 0
}

func (g *Group) EqualDashboardPermissions(other *Group) bool {
	if g == nil || other == nil {
		return g == nil && other == nil
	}
	if len(g.Dashboards) != len(other.Dashboards) {
		return false
	}
	// check dashboard element match by DashboardID
	grant, revoke := g.DiffPermissions(other)
	if len(grant) > 0 || len(revoke) > 0 {
		return false
	}
	return true
}

func (g *Group) DiffPermissions(other *Group) ([]*Dashboard, []*Dashboard) {
	a := make([]*Dashboard, 0, len(g.Dashboards))
	for _, d := range g.Dashboards {
		if !d.IsVisible() {
			continue
		}
		a = append(a, d)
	}
	b := make([]*Dashboard, 0, len(other.Dashboards))
	for _, d := range other.Dashboards {
		if !d.IsVisible() {
			continue
		}
		b = append(b, d)
	}
	added, changes, removed := ListDiff(a, b)
	return append(added, changes...), removed
}
