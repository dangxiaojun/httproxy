NAME=httproxy
OUTDIR=bin
GOBUILD=CGO_ENABLED=0 go build -ldflags '-w -s'

default:
	$(GOBUILD) -o $(OUTDIR)/$(NAME)

linux:
	GOARCH=amd64 GOOS=linux $(GOBUILD) -o $(OUTDIR)/$(NAME)-$@

clean:
	rm -rf $(OUTDIR)
