# Maturity Criteria

This document defines the 4 levels of maturity used to classify the state of features and implementations in the Arkhe project.

## Levels of Maturity

1. **THEOREM**: CI validated. The feature is implemented, tested, and fully integrated into the Continuous Integration pipeline. Automated tests run successfully and consistently.
2. **LEMMA**: Locally validated. The feature is implemented and passes local tests via `cargo test`, but it is not yet fully integrated or passing in the CI pipeline.
3. **INSPECTED**: Primary source manually verified. Code inspection has been performed without execution. The implementation exists and looks correct upon review, but lacks automated test validation.
4. **CONJECTURE**: Inferred or theoretical. The feature has a written specification or design, but is not yet implemented or verified in code.
