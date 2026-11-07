`timescale 1ns / 1ps

module bufferRX (
    input  logic             CLK,
    input  logic             RST,
    input  logic [7:0]       RX_DATA,
    input  logic             RX_VALID,
    input  logic             PAUSED,
    output logic [4:0]       COUNT,
    output logic             FULL,
    input  logic             FETCH,
    output logic [0:15][7:0] BLOCK,
    output logic             BLOCK_READY,
    input  logic             CLEAR,
    output logic             CLEARED
);

    localparam IDLE    = 2'd0;
    localparam OUT     = 2'd1;
    localparam RDY     = 2'd2;
    localparam CLR_RDY = 2'd3;

    logic [0:15][0:15][7:0] buffer;
    logic [4:0]             wr_blk;
    logic [3:0]             wr_byte;
    logic [3:0]             rd_blk;
    logic [1:0]             state;
    logic                   accept;

    assign COUNT  = wr_blk;
    assign FULL   = (wr_blk == 5'd16);
    assign accept = RX_VALID && !PAUSED && !FULL;

    always_ff @(posedge CLK) begin
        if (RST) begin
            buffer      <= '0;
            wr_blk      <= 5'd0;
            wr_byte     <= 4'd0;
            rd_blk      <= 4'd0;
            BLOCK       <= '0;
            BLOCK_READY <= 1'b0;
            CLEARED     <= 1'b0;
            state       <= IDLE;
        end else begin
            BLOCK_READY <= 1'b0;
            CLEARED     <= 1'b0;

            if (accept) begin
                buffer[wr_blk[3:0]][wr_byte] <= RX_DATA;
                wr_byte                      <= wr_byte + 4'd1;
                if (wr_byte == 4'd15)
                    wr_blk <= wr_blk + 5'd1;
            end

            case (state)

                IDLE: begin
                    if (FETCH) begin
                        state <= OUT;
                    end else if (CLEAR) begin
                        wr_blk  <= 5'd0;
                        wr_byte <= 4'd0;
                        rd_blk  <= 4'd0;
                        state   <= CLR_RDY;
                    end
                end

                OUT: begin
                    BLOCK  <= buffer[rd_blk];
                    rd_blk <= rd_blk + 4'd1;
                    state  <= RDY;
                end

                RDY: begin
                    BLOCK_READY <= 1'b1;
                    state       <= IDLE;
                end

                CLR_RDY: begin
                    CLEARED <= 1'b1;
                    state   <= IDLE;
                end

                default: state <= IDLE;

            endcase
        end
    end

endmodule
