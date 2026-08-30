// ruleid: go.security.exec-command
exec.Command("sh", "-c", input)
// ok: go.security.exec-command
os.Getenv("HOME")
