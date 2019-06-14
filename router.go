package main

import "context"

type Router interface {
	Connect(context.Context) error
	Close() error
	Clear(context.Context) error
	AddIP(context.Context, string) error
	RemoveIP(context.Context, string) error
	Commit(context.Context) error
}

type TestRouter struct{}

func (t *TestRouter) Connect(context.Context) error {
	return nil
}

func (t *TestRouter) Close() error {
	return nil
}

func (t *TestRouter) Clear(context.Context) error {
	return nil
}

func (t *TestRouter) AddIP(context.Context, string) error {
	return nil
}

func (t *TestRouter) RemoveIP(context.Context, string) error {
	return nil
}

func (t *TestRouter) Commit(context.Context) error {
	return nil
}
