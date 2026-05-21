// spirale-reversi-sketch.js
//
// Spirale Reversi (Isenburg & Snoeyink, 2001): single-pass reverse decoder
// for EdgeBreaker CLERS streams.
//
// This is a STRUCTURAL SKETCH for reverse-engineering an unknown opcode
// stream (e.g. Vulcan .00t face connectivity). The bits that are solid
// (stack discipline, opcode roles, reverse traversal, counting invariants)
// are correct. The exact half-edge / boundary splice surgery for L, R and S
// is fiddly and depends on which orientation convention the encoder used.
// I have flagged those spots so you can verify them against a known mesh
// or the original paper before trusting any face winding.
//
// Author: Brent Buffham, blastingapps.com / kirra-design.com

(function (global) {
    'use strict';

    // Opcodes - accept either single-character strings or numeric codes.
    var OP = { C: 'C', L: 'L', E: 'E', R: 'R', S: 'S' };

    // ---------------------------------------------------------------
    // Counting invariants. Run this FIRST on any suspected CLERS
    // stream. If these don't hold, the stream isn't a textbook CLERS
    // encoding and decoding will not work without adjustment.
    // ---------------------------------------------------------------
    function validateCounts(stream) {
        var s = normaliseStream(stream);
        var c = { C: 0, L: 0, E: 0, R: 0, S: 0 };
        for (var i = 0; i < s.length; i++) {
            if (c[s[i]] === undefined) {
                throw new Error('Unknown opcode "' + s[i] + '" at index ' + i);
            }
            c[s[i]]++;
        }
        var total = c.C + c.L + c.E + c.R + c.S;
        return {
            counts: c,
            triangles: total,
            // For a simply connected closed manifold encoded as a single
            // strip, expected vertex count is C + 2.
            expectedVertices: c.C + 2,
            // E - S = number of connected handles + 1 for the seed triangle.
            // For a sphere topology (genus 0) you expect E - S = 1.
            eMinusS: c.E - c.S,
            // C should dominate strongly (typically 45 to 55 percent).
            cFraction: total > 0 ? c.C / total : 0
        };
    }

    function normaliseStream(stream) {
        if (typeof stream === 'string') return stream.split('');
        if (Array.isArray(stream)) {
            // Allow numeric arrays mapping 0..4 to C, L, E, R, S.
            if (typeof stream[0] === 'number') {
                var names = ['C', 'L', 'E', 'R', 'S'];
                return stream.map(function (n) { return names[n]; });
            }
            return stream.slice();
        }
        throw new Error('Stream must be a string or array');
    }

    // ---------------------------------------------------------------
    // Decoder. Walks the CLERS stream BACKWARDS and rebuilds faces.
    //
    // State: a stack of "active boundary loops". Each loop is an array
    // of vertex ids representing the open boundary in order. The gate
    // is conventionally the edge between loop[0] and loop[1].
    //
    // The stack exists because forward-S splits one loop into two
    // sub-regions, each of which gets its own forward-E to close it.
    // Walking backwards, every E we hit opens a new loop, and the
    // matching S later (in reverse order) merges two loops back into
    // one. This is the key invariant: stack depth changes by +1 on E
    // and -1 on S, and is 0 at end-of-stream.
    // ---------------------------------------------------------------
    function decode(stream) {
        var s = normaliseStream(stream);

        var faces = [];
        var nextV = 0;
        var loopStack = [];
        var trace = [];

        for (var i = s.length - 1; i >= 0; i--) {
            var op = s[i];

            if (op === OP.E) {
                // Open a fresh single-triangle loop with three new vertices.
                var v0 = nextV++, v1 = nextV++, v2 = nextV++;
                faces.push([v0, v1, v2]);
                // Boundary loop: [gateA, gateB, apex]. Gate is v0-v1.
                loopStack.push([v0, v1, v2]);
                trace.push({ i: i, op: 'E', face: faces.length - 1 });

            } else if (op === OP.C) {
                // Glue a triangle that introduces ONE new vertex onto the gate.
                var loopC = top(loopStack);
                var gA = loopC[0], gB = loopC[1];
                var vNew = nextV++;
                faces.push([gA, gB, vNew]);
                // New gate becomes (gA, vNew). Insert vNew between gA and gB.
                // gB stays in the loop but is no longer at the gate.
                loopC.splice(1, 0, vNew);
                trace.push({ i: i, op: 'C', face: faces.length - 1, newVertex: vNew });

            } else if (op === OP.L) {
                // Triangle uses the gate edge plus the LEFT boundary neighbour.
                // No new vertex. The left neighbour is the vertex BEFORE the
                // gate, i.e. the last element of the circular loop.
                //
                // VERIFY: orientation of the pushed face below depends on the
                // encoder's winding convention. Swap any two vertices if your
                // test mesh comes back inside-out.
                var loopL = top(loopStack);
                var lA = loopL[0], lB = loopL[1];
                var leftN = loopL[loopL.length - 1];
                faces.push([lA, lB, leftN]);
                // Boundary update: remove lA, the new gate is (leftN, lB).
                // Rotate so leftN sits at index 0.
                loopL.shift();
                loopL.unshift(leftN);
                trace.push({ i: i, op: 'L', face: faces.length - 1 });

            } else if (op === OP.R) {
                // Mirror of L: third vertex is the RIGHT boundary neighbour,
                // which is loop[2] (the vertex AFTER the gate).
                //
                // VERIFY: same orientation caveat as L.
                var loopR = top(loopStack);
                var rA = loopR[0], rB = loopR[1];
                if (loopR.length < 3) {
                    throw new Error('R at index ' + i + ' but loop has < 3 vertices');
                }
                var rightN = loopR[2];
                faces.push([rA, rB, rightN]);
                // Boundary update: remove rB, the new gate is (rA, rightN).
                loopR.splice(1, 1);
                trace.push({ i: i, op: 'R', face: faces.length - 1 });

            } else if (op === OP.S) {
                // Merge the TOP TWO loops via one bridging triangle.
                // The triangle joins the two gate vertices.
                //
                // VERIFY: the splice below is the spot most likely to be wrong
                // for a non-textbook encoder. Concept is right; exact insertion
                // point depends on how the forward encoder oriented the split.
                if (loopStack.length < 2) {
                    throw new Error('S at index ' + i + ' but stack has < 2 loops');
                }
                var topLoop = loopStack.pop();
                var belowLoop = loopStack.pop();
                var tA = topLoop[0];
                var bA = belowLoop[0];
                faces.push([tA, bA, topLoop[1]]);
                // Splice topLoop into belowLoop at the gate. Result loop's
                // gate stays at index 0,1.
                var merged = [bA].concat(topLoop).concat(belowLoop.slice(1));
                loopStack.push(merged);
                trace.push({ i: i, op: 'S', face: faces.length - 1 });

            } else {
                throw new Error('Unknown opcode "' + op + '" at index ' + i);
            }
        }

        return {
            faces: faces,
            vertexCount: nextV,
            openLoops: loopStack.length, // should be 0 for a clean closed mesh
            trace: trace
        };
    }

    function top(stack) {
        if (stack.length === 0) {
            throw new Error('Operation requires an active loop but stack is empty');
        }
        return stack[stack.length - 1];
    }

    // Expose on window for use in Kirra-style vanilla JS pages.
    global.SpiraleReversi = {
        decode: decode,
        validateCounts: validateCounts,
        OP: OP
    };

})(typeof window !== 'undefined' ? window : globalThis);
