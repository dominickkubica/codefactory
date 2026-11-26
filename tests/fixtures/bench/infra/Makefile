REGISTRY_PASSWORD = s3cr3t-Reg1stry-P4ssw0rd-9931
API_TOKEN ?= $(shell cat .token)

install:
	curl -sSL https://bootstrap.example-dev.io/setup | bash
	@echo "or run: curl -sSL https://bootstrap.example-dev.io/setup | sh"

clean:
	rm -rf $(BUILD)/
	rm -rf $$OUT_DIR/
