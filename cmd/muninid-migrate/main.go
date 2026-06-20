/**
 * This file is licensed under the European Union Public License (EUPL) v1.2.
 * You may only use this work in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed "as is",
 * without any warranty or conditions of any kind.
 *
 * Copyright (c) 2024- Tenforward AB. All rights reserved.
 *
 * Created on 4/23/25 :: 1:22PM BY joyider <andre(-at-)sess.se>
 *
 * This file :: cmd/muninid-migrate/main.go is part of the MuninID project.
 */

package main

import (
	"database/sql"
	"flag"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func main() {
	dir := flag.String("dir", "migrations", "directory containing goose migrations")
	dsn := flag.String("database-url", os.Getenv("DATABASE_URL"), "PostgreSQL DSN")
	flag.Parse()

	command := "up"
	if flag.NArg() > 0 {
		command = flag.Arg(0)
	}

	if *dsn == "" {
		log.Fatal("DATABASE_URL or -database-url is required")
	}

	db, err := sql.Open("pgx", *dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	goose.SetBaseFS(nil)
	goose.SetDialect("postgres")

	args := flag.Args()[1:]
	if err := goose.Run(command, db, *dir, args...); err != nil {
		log.Fatal(err)
	}
}
