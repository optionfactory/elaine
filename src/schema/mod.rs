mod schema;

pub use schema::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(json: &str) -> ElaineManifest {
        serde_json::from_str(json).expect("valid manifest fixture")
    }

    #[test]
    fn parses_minimal_manifest() {
        let m = manifest(r#"{ "schema_version": 1, "name": "acme" }"#);
        assert_eq!(m.name, "acme");
    }

    #[test]
    fn parses_governance_metadata() {
        let m = manifest(
            r#"{
            "schema_version": 1,
            "name": "acme",
            "type": "service",
            "tier": "tier1",
            "lifecycle": "active",
            "compliance": {
                "dora": "non-critical",
                "cra": "default",
                "nis2": "important-entity",
                "ai_act": "out-of-scope",
                "gdpr": "controller",
                "data_residency": "eu",
                "ads": "internal"
            }
        }"#,
        );
        assert_eq!(m.tier, Some(ServiceTier::Tier1));
        assert_eq!(m.project_type, Some(ProjectType::Service));
        assert_eq!(m.compliance.as_ref().unwrap().gdpr, GdprRole::Controller);
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let result: Result<ElaineManifest, _> = serde_json::from_str(
            r#"{
            "schema_version": 1,
            "name": "acme",
            "bogus_field": true
        }"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_tier_value() {
        let result: Result<ElaineManifest, _> = serde_json::from_str(
            r#"{
            "schema_version": 1,
            "name": "acme",
            "tier": "tier-9"
        }"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_missing_name() {
        let result: Result<ElaineManifest, _> = serde_json::from_str(r#"{ "schema_version": 1 }"#);
        assert!(result.is_err());
    }
}
