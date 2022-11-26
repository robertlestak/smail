package persist

import "fmt"

type DriverName string

var (
	DriverFS     DriverName = "fs"
	DriverClient Driver
)

type Driver interface {
	Init() error
	Store(dir string, id string, data any) error
	Load(dir string, id string, obj any) error
	DirList(dir string) ([]string, error)
	Delete(dir string, id string) error
	MsgDir() string
	AddrDir() string
}

func LoadDriver(name DriverName) (Driver, error) {
	switch name {
	case DriverFS:
		d := &FS{}
		return d, nil
	default:
		return nil, fmt.Errorf("unknown driver: %s", name)
	}
}
