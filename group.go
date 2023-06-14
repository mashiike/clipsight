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
