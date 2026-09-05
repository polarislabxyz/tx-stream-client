use crate::protocol::StreamMode;
use crate::{v1, Error};

#[derive(Clone, Default)]
pub struct ResolvedFilter {
    filters: Vec<v1::ResolvedTransactionFilter>,
}
impl ResolvedFilter {
    pub fn match_all() -> Self {
        Self::default()
    }
    /// Adds an OR rule. Keys within `required` are ANDed; exclusions always win.
    pub fn rule(
        mut self,
        vote: Option<bool>,
        include: &[&str],
        exclude: &[&str],
        required: &[&str],
    ) -> Result<Self, Error> {
        if self.filters.len() >= 16 {
            return Err(Error::InvalidFilter("maximum 16 rules"));
        }
        if include.len() + exclude.len() + required.len() > 256 {
            return Err(Error::InvalidFilter("maximum 256 keys per rule"));
        }
        fn keys(values: &[&str]) -> Result<Vec<Vec<u8>>, Error> {
            let mut result = Vec::with_capacity(values.len());
            for value in values {
                let mut bytes = [0u8; 32];
                let len = bs58::decode(value)
                    .onto(&mut bytes)
                    .map_err(|_| Error::InvalidFilter("key must be base58 encoding 32 bytes"))?;
                if len != 32 {
                    return Err(Error::InvalidFilter("key must encode 32 bytes"));
                }
                if result.contains(&bytes.to_vec()) {
                    return Err(Error::InvalidFilter("duplicate key"));
                }
                result.push(bytes.to_vec());
            }
            Ok(result)
        }
        self.filters.push(v1::ResolvedTransactionFilter {
            vote,
            account_include: keys(include)?,
            account_exclude: keys(exclude)?,
            account_required: keys(required)?,
        });
        Ok(self)
    }
    pub(crate) fn mode(&self) -> StreamMode {
        if self.filters.is_empty()
            || self.filters.iter().any(|f| {
                f.vote.is_none()
                    && f.account_include.is_empty()
                    && f.account_exclude.is_empty()
                    && f.account_required.is_empty()
            })
        {
            StreamMode::MatchAll
        } else {
            StreamMode::Filtered
        }
    }
    pub fn into_request(self) -> v1::SubscribeResolvedTransactionsRequest {
        v1::SubscribeResolvedTransactionsRequest {
            filters: self.filters,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_keys_and_stream_mode() {
        let key = "11111111111111111111111111111111";
        assert!(ResolvedFilter::match_all()
            .rule(None, &["bad"], &[], &[])
            .is_err());
        assert!(ResolvedFilter::match_all()
            .rule(None, &[key, key], &[], &[])
            .is_err());
        assert_eq!(ResolvedFilter::match_all().mode(), StreamMode::MatchAll);
        assert_eq!(
            ResolvedFilter::match_all()
                .rule(Some(false), &[], &[], &[])
                .unwrap()
                .mode(),
            StreamMode::Filtered
        );
    }
}
