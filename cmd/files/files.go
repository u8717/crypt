package main

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/u8717/crypt/internal/store"
)

// TODO Make changing secrets possible
// TODO Index
// TODO more unittests
var encryptionToken store.Secret
var integrityToken store.Secret
var namespace string
var page int
var pageSize int
var sortKeys bool

var createCmd = &cobra.Command{
	Use:   "create <id> <value>",
	Short: "Create a new item",
	Run:   createCommandFunc,
}

var deleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete an item",
	Run:   deleteCommandFunc,
}

var updateCmd = &cobra.Command{
	Use:   "update <id> <value>",
	Short: "Update an item",
	Run:   updateCommandFunc,
}

var mergeCmd = &cobra.Command{
	Use:   "merge <id> <entry>",
	Short: "Merge an item",
	Run:   mergeCommandFunc,
}

var getCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Get an item",
	Run:   getCommandFunc,
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered keys per namespace",
	Run:   listCommandFunc,
}

func getStore() store.Records {
	return store.NewManger(".")
}

var rootCmd = &cobra.Command{
	Use:   "files engine",
	Short: "A simple and secure key-value store",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

func createCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		slog.Error("Insufficient arguments for create command.")
		cmd.Help()
		return
	}

	id := args[0]
	key, err := validateFlags(id, "create")
	if err != nil {
		slog.Error("Creating item", "id", id, "error", err)
		return
	}
	err = getStore().Register(integrityToken, encryptionToken, key)
	if err != nil {
		slog.Error("Creating item", "id", id, "error", err)
		return
	}
	if len(args) <= 1 {
		return
	}
	value := args[1]

	if value == "" {
		return
	}

	ts := time.Now().UTC()
	signature, payload, err := getStore().Insert(integrityToken, encryptionToken, ts, key, value)
	if err != nil {
		slog.Error("Creating item", "id", id, "value", value, "error", err)
		return
	}
	fmt.Printf("%s%s%s%s%s%s%s\n", signature, store.SPERATE, ts.Format(store.RFC3339Nano), store.SPERATE, id, store.SPERATE, payload)

}

func deleteCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		slog.Error("Insufficient arguments for delete command.")
		cmd.Help()
		return
	}

	id := args[0]
	key, err := validateFlags(id, "delete")
	if err != nil {
		slog.Error("Deleting item", "id", id, "error", err)
		return
	}
	slog.Debug("Deleting item", "id", id)

	err = getStore().Delete(integrityToken, encryptionToken, key)
	if err != nil {
		slog.Error("Deleting item", "id", id, "error", err)
		return
	}
}

func updateCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		slog.Error("Insufficient arguments for update command.")
		cmd.Help()
		return
	}

	id := args[0]
	value := args[1]

	slog.Debug("Updating item", "id", id, "value", value)
	ts := time.Now().UTC()
	key, err := validateFlags(id, "update")
	if err != nil {
		slog.Error("Updating item", "id", id, "error", err)
		return
	}
	signature, payload, err := getStore().Insert(integrityToken, encryptionToken, ts, key, value)
	if err != nil {
		slog.Error("Updating item", "id", id, "error", err)
		return
	}
	fmt.Printf("%s%s%s%s%s%s%s\n", signature, store.SPERATE, ts.Format(store.RFC3339Nano), store.SPERATE, id, store.SPERATE, payload)
}

func mergeCommandFunc(cmd *cobra.Command, args []string) {

	input := strings.Join(args[0:], " ")
	slog.Debug("Merging item", "value", input)

	recs, err := store.Deserialize(integrityToken, input)
	if err != nil {
		slog.Error("Merging item", "error", err)
		return
	}
	if len(recs) != 1 {
		err := fmt.Errorf("expected one element")
		slog.Error("Merging item", "error", err)
		return
	}
	rec := recs[0]
	_, err = validateFlags(fmt.Sprintf("%v", rec.Key.Identifier), "merge")
	if err != nil {
		slog.Error("Merging item", "id", rec.Key.Identifier, "error", err)
		return
	}
	errs := getStore().Import(integrityToken, encryptionToken, rec)
	for _, err2 := range errs {
		if err2 != nil {
			slog.Error("Merging item", "error", err2)
			return
		}
	}
}

func getCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		slog.Error("Insufficient arguments for get command.")
		cmd.Help()
		return
	}

	id := args[0]

	key, err := validateFlags(id, "get")
	if err != nil {
		slog.Error("Getting item", "id", id, "error", err)
		return
	}
	slog.Debug("Getting item", "id", id)
	rec, err := getStore().Get(integrityToken, encryptionToken, key)
	if err != nil {
		slog.Error("Getting value", "id", id, "error", err)
		return
	}
	fmt.Printf("%s%s%s%s%s%s%s\n", rec.Signature, store.SPERATE, rec.TS, store.SPERATE, id, store.SPERATE, rec.Payload)
}

func listCommandFunc(cmd *cobra.Command, args []string) {
	slog.Debug("Listing keys")

	keys, err := getStore().Keys(namespace, sortKeys, pageSize, page)
	if err != nil {
		slog.Error("Listing keys", "error", err)
		return
	}
	fmt.Printf("%v\n", keys)
}

func validateFlags(id, mode string) (store.Key, error) {
	if integrityToken == "" {
		return store.Key{}, fmt.Errorf("integrityToken is required")
	}
	k, err := store.NewKey(namespace, id)
	if err != nil {
		slog.Error("key or namespace is not valid.", "error", err)
		return store.Key{}, err
	}
	slog.Debug("executing command", "id", id, "namespace", namespace, "command", mode)
	return k, nil
}

func init() {
	rootCmd.PersistentFlags().StringVarP(
		(*string)(&encryptionToken),
		"encryptionToken", "k", "",
		"encryptionToken is used for encrypting and decrypting data. Use this option when you need to protect sensitive information by storing it securely.",
	)
	rootCmd.PersistentFlags().StringVarP(
		(&namespace),
		"namespace", "n", "default",
		"namespace is used to 'group' together key's, a key then cannot be directly accessed without providing the namespace. It omited namespace will be set to default",
	)

	rootCmd.PersistentFlags().StringVarP(
		(*string)(&integrityToken),
		"integrityToken", "s", "",
		"Integrity token used for signing and verifying data integrity. Setting this is required to ensure data consistency, validate the integrity, and verify the authenticity of the data.",
	)
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(mergeCmd)
	rootCmd.AddCommand(listCmd)
	listCmd.PersistentFlags().BoolVarP(
		&sortKeys,
		"sort", "r", false,
		"Sort keys based on the specified criteria. Supported values: 'id', 'timestamp', 'value', etc.",
	)

	listCmd.PersistentFlags().IntVarP(
		&page,
		"page", "p", 1,
		"Page number for pagination.",
	)

	listCmd.PersistentFlags().IntVarP(
		&pageSize,
		"pagesize", "s", 10,
		"Number of keys to display per page.",
	)

}

// TODO rewritte this to be able to parse logs
// TODO add subcommand to get a file via stdin
func ReadLinesFromReader(reader io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(reader)
	lines := make([]string, 0)

	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		slog.Error("Could not start main", "error", err)
		return
	}
}
