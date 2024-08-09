package filter

import (
	"github.com/sagernet/serenity/common/metadata"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func init() {
	filters = append(filters, filterDc)
}

func filterDc(metadata metadata.Metadata, options *option.Options) error {
	if metadata.IsDanceCrate() {
		return nil
	}
	for idx, outbound := range options.Outbounds {
		if outbound.Type == C.TypeURLTest {
			filterDcUrltestInplace(&options.Outbounds[idx].URLTestOptions)
		}
		if outbound.Type == C.TypeWireGuard {
			filterDcWireGuardInplace(&options.Outbounds[idx].WireGuardOptions)
		}
	}
	return nil
}

func filterDcUrltestInplace(o *option.URLTestOutboundOptions) {
	o.MaxSuccessiveFailures = 0
}

func filterDcWireGuardInplace(o *option.WireGuardOutboundOptions) {
	o.IdleTimeout = 0
}
