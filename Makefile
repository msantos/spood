
REBAR=$(shell which rebar || echo ./rebar)

all: deps compile

compile:
	@$(REBAR) compile

clean:  
	@$(REBAR) clean

deps:
	@$(REBAR) get-deps
