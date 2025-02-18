fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .build_transport(true)
        .compile_protos(
            &[
                "protofiles/software/v1.proto",
                "protofiles/admin_client/v1.proto",
            ],
            &["protofiles/"],
        )?;
    Ok(())
}
