use std::{future::Future, time::Duration};

use anyhow::anyhow;

use crate::outbound::context::active_dial_context;

pub(crate) async fn run_dial_phase<F>(
    fallback_timeout_ms: u64,
    phase: &'static str,
    future: F,
) -> anyhow::Result<F::Output>
where
    F: Future,
{
    if let Some(context) = active_dial_context() {
        if context.remaining_timeout().is_zero() {
            return Err(anyhow!("{phase} timed out"));
        }
        tokio::select! {
            biased;
            _ = context.cancellation.cancelled() => Err(anyhow!("{phase} cancelled")),
            result = future => Ok(result),
            _ = tokio::time::sleep_until(context.deadline.into()) => {
                Err(anyhow!("{phase} timed out"))
            }
        }
    } else {
        tokio::time::timeout(Duration::from_millis(fallback_timeout_ms), future)
            .await
            .map_err(|_| anyhow!("{phase} timed out"))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        outbound::context::{scope_dial_context, DialContext},
        routing::Destination,
    };

    use super::run_dial_phase;

    #[tokio::test]
    async fn uses_total_context_deadline_and_phase_name() {
        let context = DialContext::new(Destination::new("example.com", 443), 10);
        let error = scope_dial_context(&context, async {
            run_dial_phase(1_000, "test handshake", async {
                tokio::time::sleep(Duration::from_millis(50)).await;
            })
            .await
        })
        .await
        .expect_err("phase must time out");
        assert_eq!(error.to_string(), "test handshake timed out");
    }
}
