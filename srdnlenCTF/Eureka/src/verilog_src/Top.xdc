set_property -dict { PACKAGE_PIN L17 IOSTANDARD LVCMOS33 } [get_ports { CLK }]
create_clock -add -name sys_clk_pin -period 83.33 -waveform {0 41.66} [get_ports { CLK }]

set_property -dict { PACKAGE_PIN B18 IOSTANDARD LVCMOS33 } [get_ports { BTN_F }]

set_property -dict { PACKAGE_PIN M3  IOSTANDARD LVCMOS33 PULLUP true } [get_ports { RX }]
set_property -dict { PACKAGE_PIN L3  IOSTANDARD LVCMOS33 } [get_ports { TX }]

set_property -dict { PACKAGE_PIN R3  IOSTANDARD LVCMOS33 PULLDOWN true } [get_ports { RST }]

set_property CFGBVS VCCO [current_design]
set_property CONFIG_VOLTAGE 3.3 [current_design]
