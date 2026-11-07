`timescale 1ns / 1ps

module Top #(
    parameter CLKS_PER_BIT    = 104,
    parameter DEBOUNCE_CYCLES = 240000
)(
    input  logic CLK,
    input  logic RST,
    input  logic BTN_F,
    input  logic RX,
    output logic TX
);

    (* ASYNC_REG = "TRUE" *) logic rst_meta = 1'b1;
    (* ASYNC_REG = "TRUE" *) logic rst_sync = 1'b1;

    always @(posedge CLK) begin
        rst_meta <= RST;
        rst_sync <= rst_meta;
    end

    logic [7:0] rx_data;
    logic       rx_valid;
    logic [7:0] tx_data;
    logic       tx_send;
    logic       tx_busy;

    logic start;

    logic [0:10][0:15][7:0] k;
    logic                   ks_done;
    logic [0:3][7:0]        ks_sbox_addr;
    logic [0:3][7:0]        ks_sbox_data;

    logic [0:15][7:0] aes_sbox_addr;
    logic             aes_sbox_inv;
    logic [0:15][7:0] aes_sbox_data;
    logic [0:15][7:0] mix_block_out;
    logic             mix_start;
    logic [0:15][7:0] mix_block_in;
    logic             mix_ready;
    logic [0:15][7:0] imix_block_out;
    logic             imix_start;
    logic [0:15][7:0] imix_block_in;
    logic             imix_ready;

    logic [0:15][7:0] cr_aes_block_out;
    logic             cr_aes_dec;
    logic             cr_aes_start;
    logic [0:15][7:0] cr_aes_block_in;
    logic             cr_aes_ready;

    logic             rx_paused;
    logic [4:0]       rx_count;
    logic             rx_full;
    logic             rx_fetch;
    logic [0:15][7:0] rx_block;
    logic             rx_block_ready;
    logic             rx_clear;
    logic             rx_cleared;

    logic [0:15][7:0] tx_block;
    logic             tx_push;
    logic             tx_ready;
    logic             tx_go;
    logic             tx_done;

    uartRX #(.CLKS_PER_BIT(CLKS_PER_BIT)) u_uartRX (
        .CLK   (CLK),
        .RST   (rst_sync),
        .RX    (RX),
        .DATA  (rx_data),
        .VALID (rx_valid)
    );

    uartTX #(.CLKS_PER_BIT(CLKS_PER_BIT)) u_uartTX (
        .CLK  (CLK),
        .RST  (rst_sync),
        .DATA (tx_data),
        .SEND (tx_send),
        .TX   (TX),
        .BUSY (tx_busy)
    );

    Button #(.DEBOUNCE_CYCLES(DEBOUNCE_CYCLES)) u_Button (
        .CLK   (CLK),
        .RST   (rst_sync),
        .BTN_F (BTN_F),
        .START (start)
    );

    KeyScheduler u_KeyScheduler (
        .CLK       (CLK),
        .RST       (rst_sync),
        .K         (k),
        .KEY_DONE  (ks_done),
        .SBOX_ADDR (ks_sbox_addr),
        .SBOX_DATA (ks_sbox_data)
    );

    SboxMem u_SboxMem (
        .AES_ADDR (aes_sbox_addr),
        .AES_INV  (aes_sbox_inv),
        .AES_DATA (aes_sbox_data),
        .KS_ADDR  (ks_sbox_addr),
        .KS_DATA  (ks_sbox_data)
    );

    MixColumns u_MixColumns (
        .CLK       (CLK),
        .RST       (rst_sync),
        .BLOCK_IN  (mix_block_out),
        .START     (mix_start),
        .BLOCK_OUT (mix_block_in),
        .READY     (mix_ready)
    );

    InvMixColumns u_InvMixColumns (
        .CLK       (CLK),
        .RST       (rst_sync),
        .BLOCK_IN  (imix_block_out),
        .START     (imix_start),
        .BLOCK_OUT (imix_block_in),
        .READY     (imix_ready)
    );

    AesCore u_AesCore (
        .CLK            (CLK),
        .RST            (rst_sync),
        .K              (k),
        .BLOCK_IN       (cr_aes_block_out),
        .DEC            (cr_aes_dec),
        .START          (cr_aes_start),
        .BLOCK_OUT      (cr_aes_block_in),
        .READY          (cr_aes_ready),
        .SBOX_ADDR      (aes_sbox_addr),
        .SBOX_INV       (aes_sbox_inv),
        .SBOX_DATA      (aes_sbox_data),
        .MIX_BLOCK_OUT  (mix_block_out),
        .MIX_START      (mix_start),
        .MIX_BLOCK_IN   (mix_block_in),
        .MIX_READY      (mix_ready),
        .IMIX_BLOCK_OUT (imix_block_out),
        .IMIX_START     (imix_start),
        .IMIX_BLOCK_IN  (imix_block_in),
        .IMIX_READY     (imix_ready)
    );

    bufferRX u_bufferRX (
        .CLK         (CLK),
        .RST         (rst_sync),
        .RX_DATA     (rx_data),
        .RX_VALID    (rx_valid),
        .PAUSED      (rx_paused),
        .COUNT       (rx_count),
        .FULL        (rx_full),
        .FETCH       (rx_fetch),
        .BLOCK       (rx_block),
        .BLOCK_READY (rx_block_ready),
        .CLEAR       (rx_clear),
        .CLEARED     (rx_cleared)
    );

    Crypto u_Crypto (
        .CLK            (CLK),
        .RST            (rst_sync),
        .START          (start),
        .KEY_DONE       (ks_done),
        .RX_PAUSED      (rx_paused),
        .RX_COUNT       (rx_count),
        .RX_FULL        (rx_full),
        .RX_FETCH       (rx_fetch),
        .RX_BLOCK       (rx_block),
        .RX_BLOCK_READY (rx_block_ready),
        .RX_CLEAR       (rx_clear),
        .RX_CLEARED     (rx_cleared),
        .AES_BLOCK_OUT  (cr_aes_block_out),
        .AES_DEC        (cr_aes_dec),
        .AES_START      (cr_aes_start),
        .AES_BLOCK_IN   (cr_aes_block_in),
        .AES_READY      (cr_aes_ready),
        .TX_BLOCK       (tx_block),
        .TX_PUSH        (tx_push),
        .TX_READY       (tx_ready),
        .TX_SEND        (tx_go),
        .TX_DONE        (tx_done)
    );

    bufferTX u_bufferTX (
        .CLK     (CLK),
        .RST     (rst_sync),
        .BLOCK   (tx_block),
        .PUSH    (tx_push),
        .READY   (tx_ready),
        .SEND    (tx_go),
        .DONE    (tx_done),
        .TX_BUSY (tx_busy),
        .TX_DATA (tx_data),
        .TX_SEND (tx_send)
    );

endmodule
