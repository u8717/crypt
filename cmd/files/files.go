package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"log/slog"
	"sort"

	"github.com/spf13/cobra"
	"github.com/u8717/crypt/libstore"
)

var (
	location string
	token    string
	page     int
	pageSize int
	sortKeys bool
)

// Command definitions
var (
	createCmd = &cobra.Command{
		Use:   "create <id> <value>",
		Short: "Create a new item",
		Run:   createCommandFunc,
	}

	deleteCmd = &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete an item",
		Run:   deleteCommandFunc,
	}

	updateCmd = &cobra.Command{
		Use:   "update <id> <value>",
		Short: "Update an item",
		Run:   updateCommandFunc,
	}

	getCmd = &cobra.Command{
		Use:   "get <id>",
		Short: "Get an item",
		Run:   getCommandFunc,
	}

	listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all registered keys",
		Run:   listCommandFunc,
	}

	rootCmd = &cobra.Command{
		Use:   "files engine",
		Short: "A simple and secure key-value store",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
)

// Initialize the store
func getStore() libstore.Ops {
	if len(token) < 64 {
		log.Fatalf("Master token must be at least 64 bytes long.")
	}
	encryptionToken := token[:32]
	integrityToken := token[32:]

	ops, err := libstore.NewFileOps(".")
	if err != nil {
		log.Fatalf("Failed to initialize file operations: %v", err)
	}
	manager, err := libstore.NewManager(ops, []byte(encryptionToken), []byte(integrityToken), sha256.New)
	if err != nil {
		log.Fatalf("Failed to initialize cryptographic manager: %v", err)
	}
	return manager
}

// Create command function
func createCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		slog.Error("Insufficient arguments for create command.")
		err := cmd.Help()
		if err != nil {
			log.Fatalf(err.Error())
		}
		return
	}

	id, value := args[0], ""
	if len(args) > 1 {
		value = args[1]
	}

	store := getStore()
	if err := store.Create(id); err != nil {
		slog.Error("Failed to create item", "id", id, "error", err)
		return
	}

	if value != "" {
		if err := store.AppendTo(id, []byte(value)); err != nil {
			slog.Error("Failed to append value", "id", id, "value", value, "error", err)
		}
	}
}

// Delete command function
func deleteCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		slog.Error("Insufficient arguments for delete command.")
		err := cmd.Help()
		if err != nil {
			log.Fatalf(err.Error())
		}
		return
	}

	id := args[0]
	slog.Debug("Deleting item", "id", id)

	if err := getStore().Delete(id); err != nil {
		slog.Error("Failed to delete item", "id", id, "error", err)
	}
}

// Update command function
func updateCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		slog.Error("Insufficient arguments for update command.")
		err := cmd.Help()
		if err != nil {
			log.Fatalf(err.Error())
		}
		return
	}

	id, value := args[0], args[1]
	slog.Debug("Updating item", "id", id, "value", value)

	if err := getStore().AppendTo(id, []byte(value)); err != nil {
		slog.Error("Failed to update item", "id", id, "error", err)
	}
}

// Get command function
func getCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		slog.Error("Insufficient arguments for get command.")
		err := cmd.Help()
		if err != nil {
			log.Fatalf(err.Error())
		}
		return
	}

	id := args[0]
	slog.Debug("Getting item", "id", id)

	rec, err := getStore().ReadLast(id)
	if err != nil {
		slog.Error("Failed to get item", "id", id, "error", err)
		return
	}
	fmt.Printf("%s\n", rec)
}

// List command function
func listCommandFunc(cmd *cobra.Command, args []string) {
	slog.Debug("Listing keys")

	keys, err := getStore().List()
	if err != nil {
		slog.Error("Failed to list keys", "error", err)
		return
	}

	if sortKeys {
		sort.Strings(keys)
	}

	start := (page - 1) * pageSize
	end := start + pageSize
	if start > len(keys) {
		start, end = 0, 0
	} else if end > len(keys) {
		end = len(keys)
	}

	fmt.Printf("%v\n", keys[start:end])
}

func init() {
	rootCmd.PersistentFlags().StringVarP(
		&token,
		"key", "k", "",
		"key used for both encrypting/decrypting and signing/verifying data.",
	)

	rootCmd.PersistentFlags().StringVarP(
		&location,
		"location", "l", "",
		"Root folder for the filesystem.",
	)
	rootCmd.AddCommand(createCmd, deleteCmd, updateCmd, getCmd, listCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Failed to execute command: %v", err)
	}
}
