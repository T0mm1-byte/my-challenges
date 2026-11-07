`timescale 1ns / 1ps

module bufferTX (
    input  logic             CLK,
    input  logic             RST,
    input  logic [0:15][7:0] BLOCK,
    input  logic             PUSH,
    output logic             READY,
    input  logic             SEND,
    output logic             DONE,
    input  logic             TX_BUSY,
    output logic [7:0]       TX_DATA,
    output logic             TX_SEND
);

    localparam IDLE      = 3'd0;
    localparam PUSH_RDY  = 3'd1;
    localparam SEND_BYTE = 3'd2;
    localparam WAIT_BUSY = 3'd3;
    localparam WAIT_DONE = 3'd4;
    localparam SEND_RDY  = 3'd5;

    logic [0:16][0:15][7:0] buffer;
    logic [4:0]             count;
    logic [4:0]             rd_blk;
    logic [3:0]             rd_byte;
    logic [2:0]             state;

    always_ff @(posedge CLK) begin
        if (RST) begin
            buffer  <= '0;
            count   <= 5'd0;
            rd_blk  <= 5'd0;
            rd_byte <= 4'd0;
            READY   <= 1'b0;
            DONE    <= 1'b0;
            TX_DATA <= 8'd0;
            TX_SEND <= 1'b0;
            state   <= IDLE;
        end else begin
            READY <= 1'b0;
            DONE  <= 1'b0;

            case (state)

                IDLE: begin
                    if (PUSH) begin
                        buffer[count] <= BLOCK;
                        count         <= count + 5'd1;
                        state         <= PUSH_RDY;
                    end else if (SEND) begin
                        rd_blk  <= 5'd0;
                        rd_byte <= 4'd0;
                        state   <= (count == 5'd0) ? SEND_RDY : SEND_BYTE;
                    end
                end

                PUSH_RDY: begin
                    READY <= 1'b1;
                    state <= IDLE;
                end

                SEND_BYTE: begin
                    TX_DATA <= buffer[rd_blk][rd_byte];
                    TX_SEND <= 1'b1;
                    state   <= WAIT_BUSY;
                end

                WAIT_BUSY: begin
                    TX_SEND <= 1'b0;
                    if (TX_BUSY)
                        state <= WAIT_DONE;
                end

                WAIT_DONE: begin
                    if (!TX_BUSY) begin
                        if (rd_byte == 4'd15) begin
                            rd_byte <= 4'd0;
                            rd_blk  <= rd_blk + 5'd1;
                            if (rd_blk + 5'd1 == count)
                                state <= SEND_RDY;
                            else
                                state <= SEND_BYTE;
                        end else begin
                            rd_byte <= rd_byte + 4'd1;
                            state   <= SEND_BYTE;
                        end
                    end
                end

                SEND_RDY: begin
                    DONE  <= 1'b1;
                    count <= 5'd0;
                    state <= IDLE;
                end

                default: state <= IDLE;

            endcase
        end
    end

endmodule
