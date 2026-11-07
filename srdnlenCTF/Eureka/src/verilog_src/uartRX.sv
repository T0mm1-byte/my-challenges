`timescale 1ns / 1ps

module uartRX #(
    parameter CLKS_PER_BIT = 104
)(
    input  logic       CLK,
    input  logic       RST,
    input  logic       RX,
    output logic [7:0] DATA,
    output logic       VALID
);

    localparam IDLE  = 2'd0;
    localparam START = 2'd1;
    localparam BITS  = 2'd2;
    localparam STOP  = 2'd3;

    logic [1:0]  state;
    logic [15:0] count;
    logic [2:0]  bit_index;
    logic [7:0]  shift;
    logic        rx_meta;
    logic        rx_sync;

    always_ff @(posedge CLK) begin
        if (RST) begin
            rx_meta <= 1'b1;
            rx_sync <= 1'b1;
        end else begin
            rx_meta <= RX;
            rx_sync <= rx_meta;
        end
    end

    always_ff @(posedge CLK) begin
        if (RST) begin
            state     <= IDLE;
            count     <= 16'd0;
            bit_index <= 3'd0;
            shift     <= 8'd0;
            DATA      <= 8'd0;
            VALID     <= 1'b0;
        end else begin
            VALID <= 1'b0;
            case (state)

                IDLE: begin
                    count     <= 16'd0;
                    bit_index <= 3'd0;
                    if (rx_sync == 1'b0)
                        state <= START;
                end

                START: begin
                    if (count == (CLKS_PER_BIT - 1) / 2) begin
                        count <= 16'd0;
                        if (rx_sync == 1'b0)
                            state <= BITS;
                        else
                            state <= IDLE;
                    end else begin
                        count <= count + 16'd1;
                    end
                end

                BITS: begin
                    if (count == CLKS_PER_BIT - 1) begin
                        count <= 16'd0;
                        shift <= {rx_sync, shift[7:1]};
                        if (bit_index == 3'd7) begin
                            bit_index <= 3'd0;
                            state     <= STOP;
                        end else begin
                            bit_index <= bit_index + 3'd1;
                        end
                    end else begin
                        count <= count + 16'd1;
                    end
                end

                STOP: begin
                    if (count == CLKS_PER_BIT - 1) begin
                        count <= 16'd0;
                        state <= IDLE;
                        if (rx_sync == 1'b1) begin
                            DATA  <= shift;
                            VALID <= 1'b1;
                        end
                    end else begin
                        count <= count + 16'd1;
                    end
                end

                default: state <= IDLE;

            endcase
        end
    end

endmodule
