`timescale 1ns / 1ps

module MixColumns (
    input  logic             CLK,
    input  logic             RST,
    input  logic [0:15][7:0] BLOCK_IN,
    input  logic             START,
    output logic [0:15][7:0] BLOCK_OUT,
    output logic             READY
);

    localparam IDLE = 2'd0;
    localparam OUT  = 2'd1;
    localparam RDY  = 2'd2;

    logic [0:15][7:0] block;
    logic [1:0]       state;

    function automatic logic [7:0] xtime (input logic [7:0] b);
        return {b[6:0], 1'b0} ^ (b[7] ? 8'h1B : 8'h00);
    endfunction

    function automatic logic [0:3][7:0] mix_column (input logic [0:3][7:0] a);
        logic [7:0]      t;
        logic [0:3][7:0] r;
        t    = a[0] ^ a[1] ^ a[2] ^ a[3];
        r[0] = a[0] ^ t ^ xtime(a[0] ^ a[1]);
        r[1] = a[1] ^ t ^ xtime(a[1] ^ a[2]);
        r[2] = a[2] ^ t ^ xtime(a[2] ^ a[3]);
        r[3] = a[3] ^ t ^ xtime(a[3] ^ a[0]);
        return r;
    endfunction

    always_ff @(posedge CLK) begin
        if (RST) begin
            block     <= '0;
            BLOCK_OUT <= '0;
            READY     <= 1'b0;
            state     <= IDLE;
        end else begin
            READY <= 1'b0;

            case (state)

                IDLE: begin
                    if (START) begin
                        block <= BLOCK_IN;
                        state <= OUT;
                    end
                end

                OUT: begin
                    BLOCK_OUT[0:3]   <= mix_column(block[0:3]);
                    BLOCK_OUT[4:7]   <= mix_column(block[4:7]);
                    BLOCK_OUT[8:11]  <= mix_column(block[8:11]);
                    BLOCK_OUT[12:15] <= mix_column(block[12:15]);
                    state            <= RDY;
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
