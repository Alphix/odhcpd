"""odhcpd restarts on the router (leases are not persisted yet)."""


def test_router_restart_forgets_and_relearns_leases(fresh_lab):
    lab = fresh_lab
    assert lab.leases('router')['lan']
    lab.restart('router')
    assert not lab.leases('router').get('lan')
    lab.client_action('lan-client', 'renew', 'dhcp6')
    lab.wait_for(lambda: lab.leases('router').get('lan'), 20, 'the lease to come back')
