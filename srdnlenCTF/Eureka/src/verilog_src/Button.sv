`timescale 1ns / 1ps

module Button #(
    parameter DEBOUNCE_CYCLES = 240000
)(
    input  logic CLK,
    input  logic RST,
    input  logic BTN_F,
    output logic START
);

    logic f_meta, f_sync, f_stable, f_stable_d;
    logic [$clog2(DEBOUNCE_CYCLES)-1:0] f_count;

    always_ff @(posedge CLK) begin
        if (RST) begin
            f_meta     <= 1'b0;
            f_sync     <= 1'b0;
            f_stable   <= 1'b0;
            f_stable_d <= 1'b0;
            f_count    <= '0;
            START      <= 1'b0;
        end else begin
            f_meta     <= BTN_F;
            f_sync     <= f_meta;
            f_stable_d <= f_stable;

            if (f_sync == f_stable) begin
                f_count <= '0;
            end else if (f_count == DEBOUNCE_CYCLES - 1) begin
                f_stable <= f_sync;
                f_count  <= '0;
            end else begin
                f_count <= f_count + 1'b1;
            end

            START <= f_stable && !f_stable_d;
        end
    end

endmodule
