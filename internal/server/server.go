package server

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/robertlestak/smail/internal/persist"
	"github.com/robertlestak/smail/pkg/address"
	"github.com/robertlestak/smail/pkg/smail"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
)

func handlehealthcheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func Start(port, tlsCrtPath, tlsKeyPath string) error {
	l := log.WithFields(log.Fields{
		"app": "server",
		"fn":  "Start",
	})
	l.Debug("starting")
	d, err := persist.LoadDriver(persist.DriverName(os.Getenv("PERSIST_DRIVER")))
	if err != nil {
		return err
	}
	if err := d.Init(); err != nil {
		return err
	}
	r := mux.NewRouter()
	// Public Routes
	r.HandleFunc("/address/{id}", address.HandleGetByID).Methods("GET")
	r.HandleFunc("/message/store", smail.HandleStoreNewMessage).Methods("POST")
	r.HandleFunc("/health", handlehealthcheck).Methods("GET")

	// Address-wide Internal Routes
	r.HandleFunc("/addresses", address.HandleListLocalAddresses).Methods("GET")
	r.HandleFunc("/address", address.HandleCreateNewAddress).Methods("POST")

	// Address-Authenticated Internal Routes
	r.HandleFunc("/address/{id}/key", address.HandleLoadPrivKey).Methods("POST")
	r.HandleFunc("/address/{id}/key", address.HandleDeletePrivKeyByID).Methods("DELETE")
	r.HandleFunc("/address/{id}/bytes", address.HandleGetBytesUsed).Methods("GET")
	r.HandleFunc("/address/{id}", address.HandleDeleteAddressByID).Methods("DELETE")
	r.HandleFunc("/address/{id}/pubkey", address.HandleUpdateAddressPubKey).Methods("PUT")
	r.HandleFunc("/message/send", smail.HandleSendMessage).Methods("POST")
	r.HandleFunc("/messages/{id}", smail.HandleListMessagesForAddr).Methods("GET")
	r.HandleFunc("/messages/{addr_id}/{id}", smail.HandleDeleteMessageById).Methods("DELETE")
	r.HandleFunc("/messages/{addr_id}/{id}", smail.HandleGetMessageById).Methods("GET")

	var corsList []string
	if os.Getenv("CORS_LIST") != "" {
		corsList = strings.Split(os.Getenv("CORS_LIST"), ",")
	} else {
		corsList = []string{"*"}
	}
	c := cors.New(cors.Options{
		AllowedOrigins:   corsList,
		AllowedMethods:   []string{"GET", "POST", "DELETE", "PUT"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		Debug:            os.Getenv("CORS_DEBUG") == "true",
	})
	sPort := fmt.Sprintf(":%s", port)
	h := c.Handler(r)
	if tlsCrtPath != "" && tlsKeyPath != "" {
		l.Debug("starting server with TLS")
		return http.ListenAndServeTLS(sPort, tlsCrtPath, tlsKeyPath, h)
	} else {
		l.Debug("starting server without TLS")
		return http.ListenAndServe(sPort, h)
	}
}
