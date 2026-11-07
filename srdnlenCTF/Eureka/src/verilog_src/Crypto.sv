`timescale 1ns / 1ps

module Crypto (
    input  logic             CLK,
    input  logic             RST,
    input  logic             START,
    input  logic             KEY_DONE,
    output logic             RX_PAUSED,
    input  logic [4:0]       RX_COUNT,
    input  logic             RX_FULL,
    output logic             RX_FETCH,
    input  logic [0:15][7:0] RX_BLOCK,
    input  logic             RX_BLOCK_READY,
    output logic             RX_CLEAR,
    input  logic             RX_CLEARED,
    output logic [0:15][7:0] AES_BLOCK_OUT,
    output logic             AES_DEC,
    output logic             AES_START,
    input  logic [0:15][7:0] AES_BLOCK_IN,
    input  logic             AES_READY,
    output logic [0:15][7:0] TX_BLOCK,
    output logic             TX_PUSH,
    input  logic             TX_READY,
    output logic             TX_SEND,
    input  logic             TX_DONE
);

    localparam logic [0:1][0:15][7:0] FLAG = {
        8'h73, 8'h72, 8'h64, 8'h6E, 8'h6C, 8'h65, 8'h6E, 8'h7B, 8'h64, 8'h31, 8'h66, 8'h66, 8'h75, 8'h73, 8'h31, 8'h30,
        8'h6E, 8'h5F, 8'h63, 8'h30, 8'h6E, 8'h73, 8'h74, 8'h34, 8'h6E, 8'h74, 8'h73, 8'h5F, 8'h6C, 8'h30, 8'h6C, 8'h7D
    };

    localparam WAIT_KEY  = 5'd0;
    localparam IDLE      = 5'd1;
    localparam LOAD      = 5'd2;
    localparam RX_GO     = 5'd3;
    localparam RX_WAIT   = 5'd4;
    localparam RX_TAKE   = 5'd5;
    localparam AES_DRIVE = 5'd6;
    localparam AES_GO    = 5'd7;
    localparam AES_WAIT  = 5'd8;
    localparam AES_TAKE  = 5'd9;
    localparam P2_LOAD   = 5'd10;
    localparam TX_DRIVE  = 5'd11;
    localparam TX_GO     = 5'd12;
    localparam TX_WAIT   = 5'd13;
    localparam SEND_GO   = 5'd14;
    localparam SEND_WAIT = 5'd15;
    localparam CLR_GO    = 5'd16;
    localparam CLR_WAIT  = 5'd17;

    localparam PH_NONCE = 2'd0;
    localparam PH_P1    = 2'd1;
    localparam PH_P2    = 2'd2;

    logic [127:0]           ctr;
    logic [0:15][7:0]       nonce;
    logic [0:15][7:0]       prev;
    logic [0:15][7:0]       cur;
    logic [0:15][7:0]       out;
    logic [0:15][0:15][7:0] u;
    logic [4:0]             n;
    logic [4:0]             k;
    logic [4:0]             j;
    logic                   use_flag;
    logic                   last;
    logic                   dec;
    logic [1:0]             phase;
    logic [4:0]             state;

    function automatic logic [0:15][7:0] cst (input logic [4:0] v);
        return {123'd0, v};
    endfunction

    assign RX_PAUSED = (state != IDLE);

    always_ff @(posedge CLK) begin
        if (RST) begin
            ctr           <= '0;
            nonce         <= '0;
            prev          <= '0;
            cur           <= '0;
            out           <= '0;
            u             <= '0;
            n             <= 5'd0;
            k             <= 5'd0;
            j             <= 5'd0;
            use_flag      <= 1'b0;
            last          <= 1'b0;
            dec           <= 1'b0;
            phase         <= PH_NONCE;
            RX_FETCH      <= 1'b0;
            RX_CLEAR      <= 1'b0;
            AES_BLOCK_OUT <= '0;
            AES_DEC       <= 1'b0;
            AES_START     <= 1'b0;
            TX_BLOCK      <= '0;
            TX_PUSH       <= 1'b0;
            TX_SEND       <= 1'b0;
            state         <= WAIT_KEY;
        end else begin
            ctr       <= ctr + 128'd1;
            RX_FETCH  <= 1'b0;
            RX_CLEAR  <= 1'b0;
            AES_START <= 1'b0;
            TX_PUSH   <= 1'b0;
            TX_SEND   <= 1'b0;

            case (state)

                WAIT_KEY: begin
                    if (KEY_DONE)
                        state <= IDLE;
                end

                IDLE: begin
                    if (START || RX_FULL) begin
                        if (RX_COUNT == 5'd0) begin
                            use_flag <= 1'b1;
                            n        <= 5'd2;
                        end else begin
                            use_flag <= 1'b0;
                            n        <= RX_COUNT;
                        end
                        cur   <= ctr;
                        dec   <= 1'b0;
                        last  <= 1'b0;
                        phase <= PH_NONCE;
                        state <= AES_DRIVE;
                    end
                end

                LOAD: begin
                    if (use_flag) begin
                        cur   <= FLAG[k - 5'd1];
                        phase <= PH_P1;
                        dec   <= 1'b0;
                        state <= AES_DRIVE;
                    end else begin
                        state <= RX_GO;
                    end
                end

                RX_GO: begin
                    RX_FETCH <= 1'b1;
                    state    <= RX_WAIT;
                end

                RX_WAIT: begin
                    if (RX_BLOCK_READY)
                        state <= RX_TAKE;
                end

                RX_TAKE: begin
                    cur   <= RX_BLOCK;
                    phase <= PH_P1;
                    dec   <= 1'b0;
                    state <= AES_DRIVE;
                end

                AES_DRIVE: begin
                    AES_BLOCK_OUT <= cur;
                    AES_DEC       <= dec;
                    state         <= AES_GO;
                end

                AES_GO: begin
                    AES_START <= 1'b1;
                    state     <= AES_WAIT;
                end

                AES_WAIT: begin
                    if (AES_READY)
                        state <= AES_TAKE;
                end

                AES_TAKE: begin
                    case (phase)

                        PH_NONCE: begin
                            nonce <= AES_BLOCK_IN;
                            prev  <= AES_BLOCK_IN;
                            k     <= 5'd1;
                            state <= LOAD;
                        end

                        PH_P1: begin
                            u[k - 5'd1] <= AES_BLOCK_IN ^ prev ^ cst(k);
                            prev        <= cur;
                            if (k == n) begin
                                j     <= 5'd0;
                                state <= P2_LOAD;
                            end else begin
                                k     <= k + 5'd1;
                                state <= LOAD;
                            end
                        end

                        default: begin
                            out   <= AES_BLOCK_IN ^ ((j == n - 5'd1) ? nonce : u[1]);
                            u     <= {u[1:15], 128'd0};
                            state <= TX_DRIVE;
                        end

                    endcase
                end

                P2_LOAD: begin
                    cur   <= u[0];
                    phase <= PH_P2;
                    dec   <= 1'b1;
                    state <= AES_DRIVE;
                end

                TX_DRIVE: begin
                    TX_BLOCK <= out;
                    state    <= TX_GO;
                end

                TX_GO: begin
                    TX_PUSH <= 1'b1;
                    state   <= TX_WAIT;
                end

                TX_WAIT: begin
                    if (TX_READY) begin
                        if (last) begin
                            state <= SEND_GO;
                        end else if (j == n - 5'd1) begin
                            out   <= nonce;
                            last  <= 1'b1;
                            state <= TX_DRIVE;
                        end else begin
                            j     <= j + 5'd1;
                            state <= P2_LOAD;
                        end
                    end
                end

                SEND_GO: begin
                    TX_SEND <= 1'b1;
                    state   <= SEND_WAIT;
                end

                SEND_WAIT: begin
                    if (TX_DONE)
                        state <= CLR_GO;
                end

                CLR_GO: begin
                    RX_CLEAR <= 1'b1;
                    state    <= CLR_WAIT;
                end

                CLR_WAIT: begin
                    if (RX_CLEARED)
                        state <= IDLE;
                end

                default: state <= IDLE;

            endcase
        end
    end

endmodule
