package persist

import (
	"encoding/json"
	"os"
	"path"

	log "github.com/sirupsen/logrus"
)

type FS struct {
	DataDir string // the root data dir
}

func (d *FS) MsgDir() string {
	return "msgs"
}

func (d *FS) AddrDir() string {
	return "addrs"
}

func (d *FS) Init() error {
	l := log.WithFields(log.Fields{
		"app": "persist",
		"fn":  "Init",
	})
	l.Debug("starting")
	if os.Getenv("DATA_DIR") != "" {
		d.DataDir = os.Getenv("DATA_DIR")
	}
	// ensure the data dir exists
	if _, err := os.Stat(d.DataDir); os.IsNotExist(err) {
		os.MkdirAll(d.DataDir, 0755)
	}
	dir := path.Join(d.DataDir, d.AddrDir())
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0755)
	}
	dir = path.Join(d.DataDir, d.MsgDir())
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0755)
	}
	DriverClient = d
	return nil
}

func (d *FS) MsgDirBytesUsed(id string) (int64, error) {
	l := log.WithFields(log.Fields{
		"app": "persist",
		"fn":  "MsgDirBytesUsed",
	})
	l.Debug("starting")
	p := path.Join(d.DataDir, d.MsgDir(), id)
	fi, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

func (d *FS) Store(dir string, id string, data any) error {
	l := log.WithFields(log.Fields{
		"app": "persist",
		"fn":  "Store",
	})
	l.Debug("starting")
	pd := path.Join(d.DataDir, dir)
	if _, err := os.Stat(pd); os.IsNotExist(err) {
		os.MkdirAll(pd, 0755)
	}
	p := path.Join(pd, id)
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	defer f.Close()
	jd, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = f.Write(jd)
	if err != nil {
		return err
	}
	return nil
}

func (d *FS) Load(dir string, id string, obj any) error {
	l := log.WithFields(log.Fields{
		"app": "persist",
		"fn":  "Load",
	})
	l.Debug("starting")
	p := path.Join(d.DataDir, dir, id)
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	data := make([]byte, fi.Size())
	_, err = f.Read(data)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, obj)
	if err != nil {
		return err
	}
	return nil
}

func (d *FS) DirList(dir string) ([]string, error) {
	l := log.WithFields(log.Fields{
		"app": "persist",
		"fn":  "DirList",
		"dir": dir,
	})
	l.Debug("starting")
	// list all files in the dir
	p := path.Join(d.DataDir, dir)
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Readdir(-1)
	if err != nil {
		return nil, err
	}
	// create a list of the file names
	var files []string
	for _, f := range fi {
		files = append(files, f.Name())
	}
	return files, nil
}

func (d *FS) Delete(dir string, id string) error {
	l := log.WithFields(log.Fields{
		"app": "persist",
		"fn":  "Delete",
	})
	l.Debug("starting")
	p := path.Join(d.DataDir, dir, id)
	return os.Remove(p)
}
