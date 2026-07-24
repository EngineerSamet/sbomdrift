# SPDX-License-Identifier: Apache-2.0
"""sbomdrift — what became vulnerable since last time?

Existing scanners answer "what is vulnerable now". They have no memory, so they
cannot answer the question an on-call engineer actually asks: *what changed?*

sbomdrift stores component inventories from SBOMs over time, re-evaluates them
against a vulnerability oracle, and reports the diff between two evaluations.
"""

__version__ = "0.1.2"
