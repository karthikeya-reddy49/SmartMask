import importlib.util
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from avarna.cli import _Context, build_parser, cmd_seed_demo


def _setup_module():
    setup_path = Path(__file__).parents[1] / "data" / "setup_demo.py"
    spec = importlib.util.spec_from_file_location("setup_demo_seed_test", setup_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_seeder_reaches_target_and_is_repeatable(tmp_path, capsys):
    setup_demo = _setup_module()
    engine = create_engine(f"sqlite:///{tmp_path / 'demo.db'}")
    try:
        setup_demo.seed(engine, rows=12)
        with Session(engine) as session:
            customers = session.scalars(
                select(setup_demo.Customer).order_by(setup_demo.Customer.id)
            ).all()
            assert len(customers) == 12
            assert customers[0].email == "arun@example.test"
            assert customers[-1].email.endswith("@example.test")
            assert customers[-1].external_ref.startswith("DEMO-")

        setup_demo.seed(engine, rows=12)
        assert "Skipping seed" in capsys.readouterr().out
        with Session(engine) as session:
            assert session.query(setup_demo.Customer).count() == 12
    finally:
        engine.dispose()


def test_cli_documented_options_parse_with_expected_defaults():
    parser = build_parser()
    seed_args = parser.parse_args(["seed-demo"])
    assert seed_args.rows == 10_000

    create_args = parser.parse_args([
        "users", "create", "--username", "alice", "--role", "Support",
    ])
    assert create_args.username == "alice"
    assert create_args.role == "Support"

    grant_args = parser.parse_args([
        "users", "grant", "--username", "alice", "--permission", "data:read",
    ])
    assert grant_args.username == "alice"
    assert grant_args.permission == "data:read"


def test_seed_demo_command_forwards_requested_row_target(env):
    from argparse import Namespace

    config, manager, _ = env
    context = _Context(config)
    context.db_manager = manager
    assert cmd_seed_demo(Namespace(rows=12), context) == 0

    with Session(manager.source_engine) as session:
        assert session.query(_setup_module().Customer).count() == 12
