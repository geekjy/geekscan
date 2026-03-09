package workflow

import (
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"go.temporal.io/sdk/workflow"
)

type PortScanInput struct {
	IPs     []string           `json:"ips"`
	Options model.NaabuOptions `json:"options"`
}

type PortScanOutput struct {
	OpenPorts []model.PortResult `json:"open_ports"`
}

func PortScanWorkflow(ctx workflow.Context, input PortScanInput) (*PortScanOutput, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("PortScanWorkflow started", "ipCount", len(input.IPs))

	ao := workflow.ActivityOptions{
		StartToCloseTimeout: 20 * time.Minute,
		HeartbeatTimeout:    60 * time.Second,
	}
	ctx = workflow.WithActivityOptions(ctx, ao)

	chunkSize := input.Options.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 500
	}

	portRanges := resolvePortStrategy(input.Options)
	chunks := splitPortRange(portRanges, chunkSize)

	var futures []workflow.Future
	for _, ip := range input.IPs {
		for _, chunk := range chunks {
			f := workflow.ExecuteActivity(ctx, "NaabuScanActivity", NaabuScanInput{
				Host:    ip,
				Ports:   chunk,
				Options: input.Options,
			})
			futures = append(futures, f)
		}
	}

	output := &PortScanOutput{}
	seen := make(map[string]bool)
	for _, f := range futures {
		var result NaabuScanOutput
		if err := f.Get(ctx, &result); err != nil {
			logger.Warn("naabu chunk failed", "error", err)
			continue
		}
		for _, p := range result.OpenPorts {
			key := p.IP + ":" + string(rune(p.Port)) + ":" + p.Protocol
			if !seen[key] {
				seen[key] = true
				output.OpenPorts = append(output.OpenPorts, p)
			}
		}
	}

	logger.Info("PortScanWorkflow completed", "openPorts", len(output.OpenPorts))
	return output, nil
}

type NaabuScanInput struct {
	Host    string             `json:"host"`
	Ports   model.PortChunk    `json:"ports"`
	Options model.NaabuOptions `json:"options"`
}

type NaabuScanOutput struct {
	OpenPorts []model.PortResult `json:"open_ports"`
}

func resolvePortStrategy(opts model.NaabuOptions) []model.PortChunk {
	switch opts.PortStrategy {
	case "full":
		return []model.PortChunk{{Start: 1, End: 65535}}
	case "top100":
		return []model.PortChunk{{Start: 1, End: 100}}
	case "top1000":
		return []model.PortChunk{{Start: 1, End: 1000}}
	case "custom":
		return []model.PortChunk{{Start: 1, End: 65535}}
	default:
		return []model.PortChunk{{Start: 1, End: 1000}}
	}
}

func splitPortRange(ranges []model.PortChunk, chunkSize int) []model.PortChunk {
	var chunks []model.PortChunk
	for _, r := range ranges {
		for start := r.Start; start <= r.End; start += chunkSize {
			end := start + chunkSize - 1
			if end > r.End {
				end = r.End
			}
			chunks = append(chunks, model.PortChunk{Start: start, End: end})
		}
	}
	return chunks
}
