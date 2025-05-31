/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package workload

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils/connection"
)

// LimiterConfig is used to create a limiter.
type LimiterConfig struct {
	Endpoint     connection.Endpoint `mapstructure:"endpoint"`
	InitialLimit int                 `mapstructure:"initial-limit"`
}

// NewLimiter instantiate a new rate limiter with optional remote control capabilities.
func NewLimiter(c *LimiterConfig, burst int) *rate.Limiter {
	if c == nil {
		return getLimiter(0, burst)
	}

	limiter := getLimiter(c.InitialLimit, burst)

	// Allow fixed limit.
	if c.Endpoint.Empty() {
		return limiter
	}

	// start remote-limiter controller.
	logger.Infof("Start remote controller listener on %s\n", c.Endpoint.Address())
	logger.Infof("Serving...")
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.POST("/setLimits", func(c *gin.Context) {
		logger.Infof("Received limit request.")

		type LimitRequest struct {
			Limit int `json:"limit"`
		}

		var request LimitRequest
		if err := c.BindJSON(&request); err != nil {
			logger.Errorf("error deserializing request: %v", err)
		}
		logger.Infof("Setting limit to %d", request.Limit)

		limiter.SetLimit(getRate(request.Limit))
		c.IndentedJSON(http.StatusOK, request)
	})
	go func() {
		err := router.Run(c.Endpoint.Address())
		if err != nil {
			logger.Errorf("Error running rate limit remote controller: %s", err)
		}
	}()

	return limiter
}

func getLimiter(limitPerSecond, burst int) *rate.Limiter {
	if limitPerSecond < 1 {
		logger.Debugf("Setting to unlimited (value passed: %d).", limitPerSecond)
		return rate.NewLimiter(rate.Inf, burst)
	}
	logger.Debugf("Setting limit to %d requests per second.", limitPerSecond)
	return rate.NewLimiter(getRate(limitPerSecond), burst)
}

func getRate(limitPerSecond int) rate.Limit {
	return rate.Every(time.Second / time.Duration(limitPerSecond))
}
