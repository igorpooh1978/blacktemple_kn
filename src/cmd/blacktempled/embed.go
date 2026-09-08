package main

import "embed"

//go:embed assets/*
var embeddedUI embed.FS
