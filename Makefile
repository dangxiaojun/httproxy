NAME=httproxy
OUTDIR=bin
GOBUILD=CGO_ENABLED=0 go build -ldflags '-w -s'

default:
	$(GOBUILD) -o $(OUTDIR)/$(NAME)

all: linux windows darwin

linux:
	GOARCH=amd64 GOOS=linux $(GOBUILD) -o $(OUTDIR)/$(NAME)-$@

windows:
	GOARCH=amd64 GOOS=windows $(GOBUILD) -o $(OUTDIR)/$(NAME)-$@.exe

darwin:
	GOARCH=amd64 GOOS=darwin $(GOBUILD) -o $(OUTDIR)/$(NAME)-$@

clean:
	rm -rf $(OUTDIR)
