TS_TAGS := ts_omit_peerapiserver,ts_omit_webclient,ts_omit_ssh,ts_omit_drive,ts_omit_taildrop
.PHONY: test test-secure build docker integration

test:
	go test ./...

test-secure:
	go test -tags '$(TS_TAGS)' ./...

build:
	CGO_ENABLED=0 go build -trimpath -tags '$(TS_TAGS)' -o buddybackup .

docker:
	docker build -t buddybackup:local .

integration:
	python3 integration/run.py

# Run from the exact release source before publishing the independently obtained hash.
.PHONY: zfs-host-hash
zfs-host-hash:
	@python3 -c 'import hashlib,pathlib; p=pathlib.Path("internal/buddy/zfs_host.py"); line=hashlib.sha256(p.read_bytes()).hexdigest()+"  "+str(p)+"\n"; pathlib.Path("docs/ZFS-HOST-SHA256.txt").write_text(line); print(line,end="")'
