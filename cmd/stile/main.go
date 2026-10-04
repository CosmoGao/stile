package main

import (
	"log"
	"net/http"
	"os"

	"github.com/CosmoGao/stile/internal/config"
	"github.com/CosmoGao/stile/internal/store"
	"github.com/CosmoGao/stile/internal/web"
)

func main() {
	if len(os.Args) > 1 {
		log.Fatal("stile has no subcommands; set STILE_CONFIG or the STILE_* environment variables")
	}
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	key, err := config.LoadOrCreateMasterKey(cfg.MasterKey)
	if err != nil {
		log.Fatal(err)
	}
	db, err := store.Open(cfg.Database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	srv, err := web.New(cfg, db, key)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", cfg.Listen)
	if err := http.ListenAndServe(cfg.Listen, srv.Handler()); err != nil {
		log.Fatal(err)
	}
}
