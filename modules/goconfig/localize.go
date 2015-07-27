package goconfig

type Localize struct {
	Domain    string // domain e.g: github.com
	RootDepth int    // same as modules.setting.RootPathPairs
	Download  string // git+ssh git+http git+https http https go
}
