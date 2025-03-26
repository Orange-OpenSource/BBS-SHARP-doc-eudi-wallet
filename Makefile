all: clean diagrams pdf

diagrams : 
	plantuml -o "../media" "diagrams/**.puml" -charset utf8 -checkmetadata

pdf:
	pandoc --pdf-engine=xelatex -s -V geometry:margin=1in -f markdown -t pdf -o Orange_trust_model_introduction.pdf Trust-model-Introduction.md
	pandoc --pdf-engine=xelatex -s -V geometry:margin=1in -f markdown -t pdf -o Orange_trust_model_privacy_on_attestation_presentation.pdf Trust-model-privacy-on-attestation-presentation.md

clean:
	del *.pdf

.PHONY: all clean pdf diagrams
