package build

import (
	"sort"

	"github.com/libp2p/go-libp2p-core/protocol"

	"github.com/filecoin-project/go-state-types/abi"
	v0miner "github.com/filecoin-project/specs-actors/actors/builtin/miner"

	"github.com/filecoin-project/lotus/node/modules/dtypes"
)

func DefaultSectorSize() abi.SectorSize {
	szs := make([]abi.SectorSize, 0, len(v0miner.SupportedProofTypes))
	for spt := range v0miner.SupportedProofTypes {
		ss, err := spt.SectorSize()
		if err != nil {
			panic(err)
		}

		szs = append(szs, ss)
	}

	sort.Slice(szs, func(i, j int) bool {
		return szs[i] < szs[j]
	})

	return szs[0]
}

// Core network constants

func BlocksTopic(netName dtypes.NetworkName) string   { return "/fil/blocks/" + string(netName) }
func MessagesTopic(netName dtypes.NetworkName) string { return "/fil/msgs/" + string(netName) }
func DhtProtocolName(netName dtypes.NetworkName) protocol.ID {
	return protocol.ID("/fil/kad/" + string(netName))
}

func UseNewestNetwork() bool {
	// TODO: Put these in a container we can iterate over
	if UpgradeBreezeHeight <= 0 && UpgradeSmokeHeight <= 0 {
		return true
	}
	return false
}
