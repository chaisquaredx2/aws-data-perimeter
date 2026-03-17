.PHONY: generate validate plan apply test clean

INTENT_FILE ?= config/data_perimeter_intent.yaml
OUTPUT_DIR ?= terraform/policies

generate:
	python -m generator.cli generate --intent $(INTENT_FILE) --output $(OUTPUT_DIR)

validate:
	python -m generator.cli validate --policies $(OUTPUT_DIR)

plan: generate validate
	cd terraform/environments/canary && terraform plan

apply: generate validate
	cd terraform/environments/canary && terraform apply

test:
	python -m pytest tests/ -v

clean:
	rm -f $(OUTPUT_DIR)/*.json
