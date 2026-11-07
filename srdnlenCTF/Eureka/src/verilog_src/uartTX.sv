`timescale 1ns / 1ps

module uartTX #(
    parameter CLKS_PER_BIT = 104
)(
    input  logic       CLK,
    input  logic       RST,
    input  logic [7:0] DATA,
    input  logic       SEND,
    output logic       TX,
    output logic       BUSY
);

    localparam IDLE     = 1'b0;
    localparam SHIFTING = 1'b1;

    logic        state;
    logic [15:0] count;
    logic [3:0]  bit_index;
    logic [9:0]  frame;

    always_ff @(posedge CLK) begin
        if (RST) begin
            state     <= IDLE;
            count     <= 16'd0;
            bit_index <= 4'd0;
            frame     <= 10'h3FF;
            TX        <= 1'b1;
            BUSY      <= 1'b0;
        end else begin
            case (state)

                IDLE: begin
                    TX        <= 1'b1;
                    BUSY      <= 1'b0;
                    count     <= 16'd0;
                    bit_index <= 4'd0;
                    if (SEND) begin
                        frame <= {1'b1, DATA, 1'b0};
                        BUSY  <= 1'b1;
                        state <= SHIFTING;
                    end
                end

                SHIFTING: begin
                    TX <= frame[0];
                    if (count == CLKS_PER_BIT - 1) begin
                        count <= 16'd0;
                        frame <= {1'b1, frame[9:1]};
                        if (bit_index == 4'd9) begin
                            bit_index <= 4'd0;
                            TX        <= 1'b1;
                            BUSY      <= 1'b0;
                            state     <= IDLE;
                        end else begin
                            bit_index <= bit_index + 4'd1;
                        end
                    end else begin
                        count <= count + 16'd1;
                    end
                end

            endcase
        end
    end

endmodule
