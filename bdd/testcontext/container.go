// Copyright (c) 2026 Vincent Palmer. Licensed under AGPL-3.0.
package testcontext

import (
	"context"
	"fmt"
	"sync"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	containerOnce   sync.Once
	globalContainer *PostgresContainer
	containerErr    error
)

func StartContainer(ctx context.Context) (*PostgresContainer, error) {
	containerOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				containerErr = fmt.Errorf("docker/testcontainers unavailable (panic): %v", r)
			}
		}()

		req := testcontainers.ContainerRequest{
			Image:        "postgres:16-alpine",
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_USER":     "transparenz",
				"POSTGRES_PASSWORD": "transparenz_test",
				"POSTGRES_DB":       "transparenz_bdd",
			},
			WaitingFor: wait.ForAll(
				wait.ForLog("database system is ready to accept connections"),
				wait.ForListeningPort("5432/tcp"),
			),
		}

		container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
		if err != nil {
			containerErr = fmt.Errorf("failed to start postgres container: %w", err)
			return
		}

		host, err := container.Host(ctx)
		if err != nil {
			containerErr = fmt.Errorf("failed to get container host: %w", err)
			return
		}

		mappedPort, err := container.MappedPort(ctx, "5432")
		if err != nil {
			containerErr = fmt.Errorf("failed to get mapped port: %w", err)
			return
		}

		dsn := fmt.Sprintf("host=%s port=%s user=transparenz password=transparenz_test dbname=transparenz_bdd sslmode=disable search_path=compliance",
			host, mappedPort.Port())

		globalContainer = &PostgresContainer{DSN: dsn}
	})

	return globalContainer, containerErr
}
