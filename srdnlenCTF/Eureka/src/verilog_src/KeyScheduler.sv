`timescale 1ns / 1ps

module KeyScheduler (
    input  logic                   CLK,
    input  logic                   RST,
    output logic [0:10][0:15][7:0] K,
    output logic                   KEY_DONE,
    output logic [0:3][7:0]        SBOX_ADDR,
    input  logic [0:3][7:0]        SBOX_DATA
);

    localparam IDLE      = 4'd0;
    localparam LOAD      = 4'd1;
    localparam STEP      = 4'd2;
    localparam ROT       = 4'd3;
    localparam SUB       = 4'd4;
    localparam RCON      = 4'd5;
    localparam WRITE     = 4'd6;
    localparam DONE      = 4'd7;

    localparam logic [0:15][7:0] KEY = 128'h5080664574B437FA1555008A67BF6E05;

    logic [0:43][0:3][7:0] w;
    logic [0:3][7:0]       temp;
    logic [5:0]            i;
    logic [7:0]            rc;
    logic [3:0]            state;

    function automatic logic [7:0] xtime (input logic [7:0] b);
        return {b[6:0], 1'b0} ^ (b[7] ? 8'h1B : 8'h00);
    endfunction

    assign K         = w;
    assign SBOX_ADDR = temp;

    always_ff @(posedge CLK) begin
        if (RST) begin
            w        <= '0;
            temp     <= '0;
            i        <= 6'd0;
            rc       <= 8'h01;
            KEY_DONE <= 1'b0;
            state    <= LOAD;
        end else begin
            KEY_DONE <= 1'b0;

            case (state)

                IDLE: begin
                    state <= IDLE;
                end

                LOAD: begin
                    w[0]  <= KEY[0:3];
                    w[1]  <= KEY[4:7];
                    w[2]  <= KEY[8:11];
                    w[3]  <= KEY[12:15];
                    i     <= 6'd4;
                    rc    <= 8'h01;
                    state <= STEP;
                end

                STEP: begin
                    if (i[1:0] == 2'b00) begin
                        state <= ROT;
                    end else begin
                        w[i] <= w[i-4] ^ w[i-1];
                        if (i == 6'd43)
                            state <= DONE;
                        else
                            i <= i + 6'd1;
                    end
                end

                ROT: begin
                    temp[0] <= w[i-1][1];
                    temp[1] <= w[i-1][2];
                    temp[2] <= w[i-1][3];
                    temp[3] <= w[i-1][0];
                    state   <= SUB;
                end

                SUB: begin
                    temp  <= SBOX_DATA;
                    state <= RCON;
                end

                RCON: begin
                    temp[0] <= temp[0] ^ rc;
                    rc      <= xtime(rc);
                    state   <= WRITE;
                end

                WRITE: begin
                    w[i]  <= w[i-4] ^ temp;
                    i     <= i + 6'd1;
                    state <= STEP;
                end

                DONE: begin
                    KEY_DONE <= 1'b1;
                    state    <= IDLE;
                end

                default: state <= IDLE;

            endcase
        end
    end

endmodule
