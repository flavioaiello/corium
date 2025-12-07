use corium::{Contact, Identity};
use corium::advanced::RoutingTable;

fn make_identity(byte: u8) -> Identity {
    let mut id = [0u8; 32];
    id[0] = byte;
    Identity::from_bytes(id)
}

fn make_contact(byte: u8) -> Contact {
    Contact {
        identity: make_identity(byte),
        addr: format!("node-{byte}"),
    }
}

#[test]
fn routing_table_orders_contacts_by_distance() {
    let self_id = make_identity(0x00);
    let mut table = RoutingTable::new(self_id, 4);

    let contacts = [make_contact(0x10), make_contact(0x20), make_contact(0x08)];
    for contact in &contacts {
        table.update(contact.clone());
    }

    let target = make_identity(0x18);
    let closest = table.closest(&target, 3);
    let ids: Vec<u8> = closest.iter().map(|c| c.identity.as_bytes()[0]).collect();
    assert_eq!(ids, vec![0x10, 0x08, 0x20]);
}

#[test]
fn routing_table_respects_bucket_capacity() {
    let self_id = make_identity(0x00);
    let mut table = RoutingTable::new(self_id, 2);

    let contacts = [make_contact(0x80), make_contact(0xC0), make_contact(0xA0)];
    for contact in &contacts {
        table.update(contact.clone());
    }

    let target = make_identity(0x90);
    let closest = table.closest(&target, 10);
    let ids: Vec<u8> = closest.iter().map(|c| c.identity.as_bytes()[0]).collect();
    assert_eq!(closest.len(), 2);
    assert!(ids.contains(&0x80));
    assert!(ids.contains(&0xC0));
}

#[test]
fn routing_table_truncates_when_k_changes() {
    let self_id = make_identity(0x00);
    let mut table = RoutingTable::new(self_id, 4);

    let contacts = [make_contact(0x80), make_contact(0x81), make_contact(0x82)];
    for contact in &contacts {
        table.update(contact.clone());
    }

    table.set_k(2);
    let target = make_identity(0x80);
    let closest = table.closest(&target, 10);
    assert_eq!(closest.len(), 2);
}
