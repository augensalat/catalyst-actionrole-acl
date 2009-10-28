package Catalyst::ActionRole::ACL;
use Moose::Role;
use namespace::autoclean;

our $VERSION = '0.06'; # REMEMBER TO BUMP VERSION IN Action::Role::ACL ALSO!

=head1 NAME

Catalyst::ActionRole::ACL - User role-based authorization action class

=head1 SYNOPSIS

 package MyApp::Controller::Foo;
 use Moose;
 use namespace::autoclean;

 BEGIN { extends 'Catalyst::Controller::ActionRole' }

 sub foo
 :Local
 :Does(ACL)
 :RequiresRole(admin)
 :ACLDetachTo(denied)
 {
     my ($self, $c) = @_;
     ...
 }

 sub denied :Private {
     my ($self, $c) = @_;

     $c->res->status = '403';
     $c->body('Denied!');
 }

=head1 DESCRIPTION

Provides a L<Catalyst reusable action role|Catalyst::Controller::ActionRole>
for user role-based authorization.
ACLs are applied via the assignment of attributes to
application action subroutines.

=head1 REQUIRED ATTRIBUTES

Failure to include the following required attributes will result in an exception
when the ACL::Role action's constructor is called.

=head2 ACLDetachTo

The name of an action to which the request should be detached if it is
determined that ACLs are not satisfied for this user and the resource he
is attempting to access.

=head2 RequiresRole, AllowedRole and ACLRule

The action must include at least one of these attributes, otherwise the Role::ACL
constructor will throw an exception.

=head1 Processing of ACLs

One or more roles or rules may be associated with an action.

User roles are fetched via the invocation of the context "user" object's "roles"
method.

Roles specified with the RequiresRole attribute are checked before roles
specified with the AllowedRole attribute.

Rules are a more flexible concept than the static roles evaluation. Access
control is delegated to controller methods. Rules are processed in the given
order, but before any roles. Each rule can decide to terminate the processing
chain by returning C<ALLOW> or C<DENY>. If even the last rule did not return
C<ALLOW> or C<DENY> access is granted if no roles are defined, otherwise roles
are checked as described above.

Rule controller methods are given three (besides C<$self>) arguments:

=over

=item * The well known context C<$c>.

=item * The L<action|Catalyst::Action> to which this rule was applied.

=item * A hash reference with the user's roles as keys and values set to C<1>.

=back

The mandatory ACLDetachTo attribute specifies the name of the action to which
execution will detach on access violation.

ACLs may be applied to chained actions so that different roles are required or
allowed for each link in the chain (or no roles at all).

ACLDetachTo allows us to short-circuit traversal of an action chain as soon as
access is denied to one of the actions in the chain by its ACL.

=head2 Examples

 # this is an invalid action
 sub broken
 :Local
 :Does(ACL)
 {
     my ($self, $c) = @_;
     ...
 }

 This action will cause an exception because it's missing the ACLDetachTo attribute
 and has neither a RequiresRole, AllowedRole nor an ACLRule attribute. A Role::ACL
 action must include at least one RequiresRole, AllowedRole or ACLRule attribute.

 sub foo
 :Local
 :Does(ACL)
 :RequiresRole(admin)
 :ACLDetachTo(denied)
 {
     my ($self, $c) = @_;
     ...
 }

This action may only be executed by users with the 'admin' role.

 sub bar :Local
 :Does(ACL)
 :RequiresRole(admin)
 :AllowedRole(editor)
 :AllowedRole(writer)
 :ACLDetachTo(denied)
 {
     my ($self, $c) = @_;
     ...
 }

This action requires that the user has the 'admin' role and
either the 'editor' or 'writer' role (or both).

 sub easy :Local
 :Does(ACL)
 :AllowedRole(admin)
 :AllowedRole(user)
 :ACLDetachTo(denied)
 {
     my ($self, $c) = @_;
     ...
 }

Any user with either the 'admin' or 'user' role may execute this action.

 sub edit :Local
 :Does(ACL)
 :ACLRule(assert_can_edit)
 :ACLDetachTo(denied)
 {
     my ($self, $c) = @_;
     ...
 }

 sub assert_can_edit :Private {
     my ($self, $c, $action, $roles) = @_;

     return 'ALLOW' if $roles->{admin}
     return 'DENY'  unless $roles->{editor}
     return 'DENY'
         unless $c->stash->{this}->writable_for($c->user);
     return 'CONTINUE';
 }

Admins can always edit everything, otherwise user must be an editor.
Eventually the object ("this") defines if editor has write access.
The final C<'CONTINUE'> is just to demonstrate, that access control
is delegated to any subsequent rule or role checking.

=head1 WRAPPED METHODS

=cut

=head2 C<BUILD( $args )>

Throws an exception if parameters are missing or invalid.

=cut

sub BUILD { }

after BUILD => sub {
    my $class = shift;
    my ($args) = @_;

    my $attr = $args->{attributes};

    unless (
	exists $attr->{RequiresRole} ||
	exists $attr->{AllowedRole} ||
	exists $attr->{ACLRule}
    ) {
        Catalyst::Exception->throw(
            "Action '$args->{reverse}' requires at least one ACLRule, RequiresRole or AllowedRole attribute");
    }
    unless (exists $attr->{ACLDetachTo} && $attr->{ACLDetachTo}) {
        Catalyst::Exception->throw(
            "Action '$args->{reverse}' requires the ACLDetachTo(<action>) attribute");
    }
};

=head2 C<execute( $controller, $c )>

Overrides &Catalyst::Action::execute.

In order for delegation to occur, the context 'user' object must exist (authenticated user) and
the C<can_visit> method must return a true value.

See L<Catalyst::Action|METHODS/action>

=cut

around execute => sub {
    my $orig = shift;
    my $self = shift;
    my ($controller, $c) = @_;

    if ($c->user) {
        if ($self->can_visit($c)) {
            return $self->$orig(@_);
        }
    }

    my $denied = $self->attributes->{ACLDetachTo}[0];

    $c->detach($denied);
};

=head2 C<can_visit( $c )>

Return true if the authenticated user can visit this action.

This method is useful for determining in advance if a user can execute
a given action.

=cut

sub can_visit {
    my ($self, $c) = @_;
    my $user = $c->user;

    return unless $user;

    my %user_has;

    %user_has = map {$_,1} $user->roles
	if $user->supports('roles') && $user->can('roles');

    my $attr = $self->attributes;
    my $rules = $attr->{ACLRule};

    my $rc;
    if ($rules) {
	for my $rule (@$rules) {
	    $rc = $c->forward($rule, [$self, \%user_has]) || '';
	    # Terminate access control chain if we get an explicit
	    # return value ("ALLOW" or "DENY").
	    return 1
		if $rc eq 'ALLOW';
	    return ''
		if $rc eq 'DENY';
	}
    }

    my $required = $attr->{RequiresRole};
    my $allowed = $attr->{AllowedRole};

    # Return success if now ACLRule denied access and no RequiresRole or
    # AllowedRole attribute is set.
    return 1
	unless $required or $allowed;

    if ($required && $allowed) {
        for my $role (@$required) {
            return ''
		unless $user_has{$role};
        }
        for my $role (@$allowed) {
            return 1
		if $user_has{$role};
        }
        return '';
    }
    elsif ($required) {
        for my $role (@$required) {
            return ''
		unless $user_has{$role};
        }
        return 1;
    }
    elsif ($allowed) {
        for my $role (@$allowed) {
            return 1
		if $user_has{$role};
        }
        return '';
    }

    return '';
}

1;

=head1 AUTHOR

David P.C. Wollmann E<lt>converter42@gmail.comE<gt>

=head1 CONTRIBUTORS

Converted from an action class to an action role by Tomas Doran (t0m)

=head1 BUGS

This is new code. Find the bugs and report them, please.

=head1 COPYRIGHT & LICENSE

Copyright 2009 by David P.C. Wollmann

This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

