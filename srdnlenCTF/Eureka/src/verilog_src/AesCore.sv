`timescale 1ns / 1ps

module AesCore (
    input  logic                   CLK,
    input  logic                   RST,
    input  logic [0:10][0:15][7:0] K,
    input  logic [0:15][7:0]       BLOCK_IN,
    input  logic                   DEC,
    input  logic                   START,
    output logic [0:15][7:0]       BLOCK_OUT,
    output logic                   READY,
    output logic [0:15][7:0]       SBOX_ADDR,
    output logic                   SBOX_INV,
    input  logic [0:15][7:0]       SBOX_DATA,
    output logic [0:15][7:0]       MIX_BLOCK_OUT,
    output logic                   MIX_START,
    input  logic [0:15][7:0]       MIX_BLOCK_IN,
    input  logic                   MIX_READY,
    output logic [0:15][7:0]       IMIX_BLOCK_OUT,
    output logic                   IMIX_START,
    input  logic [0:15][7:0]       IMIX_BLOCK_IN,
    input  logic                   IMIX_READY
);

    localparam IDLE      = 4'd0;
    localparam ARK_E     = 4'd1;
    localparam ARK_D     = 4'd2;
    localparam SUB       = 4'd3;
    localparam SHIFT_E   = 4'd4;
    localparam SHIFT_D   = 4'd5;
    localparam MIX_DRIVE = 4'd6;
    localparam MIX_GO    = 4'd7;
    localparam MIX_WAIT  = 4'd8;
    localparam MIX_TAKE  = 4'd9;
    localparam OUT       = 4'd10;
    localparam RDY       = 4'd11;

    localparam NROUNDS = 4'd10;

    logic [0:15][7:0] blk;
    logic [3:0]       round;
    logic             dec;
    logic [3:0]       state;

    assign SBOX_ADDR = blk;
    assign SBOX_INV  = dec;

    always_ff @(posedge CLK) begin
        if (RST) begin
            blk            <= '0;
            round          <= 4'd0;
            dec            <= 1'b0;
            BLOCK_OUT      <= '0;
            READY          <= 1'b0;
            MIX_BLOCK_OUT  <= '0;
            MIX_START      <= 1'b0;
            IMIX_BLOCK_OUT <= '0;
            IMIX_START     <= 1'b0;
            state          <= IDLE;
        end else begin
            READY      <= 1'b0;
            MIX_START  <= 1'b0;
            IMIX_START <= 1'b0;

            case (state)

                IDLE: begin
                    if (START) begin
                        blk <= BLOCK_IN;
                        dec <= DEC;
                        if (DEC) begin
                            round <= NROUNDS;
                            state <= ARK_D;
                        end else begin
                            round <= 4'd0;
                            state <= ARK_E;
                        end
                    end
                end

                ARK_E: begin
                    blk <= blk ^ K[round];
                    if (round == NROUNDS) begin
                        state <= OUT;
                    end else begin
                        round <= round + 4'd1;
                        state <= SUB;
                    end
                end

                ARK_D: begin
                    blk <= blk ^ K[round];
                    if (round == 4'd0) begin
                        state <= OUT;
                    end else begin
                        round <= round - 4'd1;
                        if (round == NROUNDS)
                            state <= SHIFT_D;
                        else
                            state <= MIX_DRIVE;
                    end
                end

                SUB: begin
                    blk   <= SBOX_DATA;
                    state <= dec ? ARK_D : SHIFT_E;
                end

                SHIFT_E: begin
                    blk[0]  <= blk[0];
                    blk[1]  <= blk[5];
                    blk[2]  <= blk[10];
                    blk[3]  <= blk[15];
                    blk[4]  <= blk[4];
                    blk[5]  <= blk[9];
                    blk[6]  <= blk[14];
                    blk[7]  <= blk[3];
                    blk[8]  <= blk[8];
                    blk[9]  <= blk[13];
                    blk[10] <= blk[2];
                    blk[11] <= blk[7];
                    blk[12] <= blk[12];
                    blk[13] <= blk[1];
                    blk[14] <= blk[6];
                    blk[15] <= blk[11];
                    if (round == NROUNDS)
                        state <= ARK_E;
                    else
                        state <= MIX_DRIVE;
                end

                SHIFT_D: begin
                    blk[0]  <= blk[0];
                    blk[1]  <= blk[13];
                    blk[2]  <= blk[10];
                    blk[3]  <= blk[7];
                    blk[4]  <= blk[4];
                    blk[5]  <= blk[1];
                    blk[6]  <= blk[14];
                    blk[7]  <= blk[11];
                    blk[8]  <= blk[8];
                    blk[9]  <= blk[5];
                    blk[10] <= blk[2];
                    blk[11] <= blk[15];
                    blk[12] <= blk[12];
                    blk[13] <= blk[9];
                    blk[14] <= blk[6];
                    blk[15] <= blk[3];
                    state   <= SUB;
                end

                MIX_DRIVE: begin
                    if (dec)
                        IMIX_BLOCK_OUT <= blk;
                    else
                        MIX_BLOCK_OUT <= blk;
                    state <= MIX_GO;
                end

                MIX_GO: begin
                    if (dec)
                        IMIX_START <= 1'b1;
                    else
                        MIX_START <= 1'b1;
                    state <= MIX_WAIT;
                end

                MIX_WAIT: begin
                    if (dec ? IMIX_READY : MIX_READY)
                        state <= MIX_TAKE;
                end

                MIX_TAKE: begin
                    blk   <= dec ? IMIX_BLOCK_IN : MIX_BLOCK_IN;
                    state <= dec ? SHIFT_D : ARK_E;
                end

                OUT: begin
                    BLOCK_OUT <= blk;
                    state     <= RDY;
                end

                RDY: begin
                    READY <= 1'b1;
                    state <= IDLE;
                end

                default: state <= IDLE;

            endcase
        end
    end

endmodule
