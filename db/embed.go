package db

import "embed"

//go:embed schema/*.sql
var Migrations embed.FS
