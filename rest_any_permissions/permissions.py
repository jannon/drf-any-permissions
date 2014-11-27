from rest_framework.permissions import BasePermission


class AnyPermissions(BasePermission):

    def get_permissions(self, view):
        """
        Get all of the permissions that are associated with the view.
        """

        permissions = getattr(view, "any_permission_classes", [])

        if not hasattr(permissions, "__iter__"):
            permissions = [permissions]

        return permissions

    def check_permissions(self, permissions, request, view, complex_perm):
        for perm_item in permissions:
            # sublist case
            if hasattr(perm_item, "__iter__"):
                # A failed sublist always returns False
                if not self.check_permissions(perm_item, request, view, self.is_complex(perm_item)):
                    return False
            else:  # single perm case
                permission = perm_item()
                if permission.has_permission(request, view):
                    if not complex_perm:
                        return True
                else:
                    if complex_perm:
                        return False

        # if we reach the end, if it's not complex, no regular list item returned true, so we return
        # False.  If we are complex, the no item failed, so we return True
        return complex_perm

    def is_complex(self, permissions):
        """
        Just check whether or not there are any sublists in the permissions
        """
        for perm in permissions:
            if hasattr(perm, "__iter__"):
                return True
        return False

    def has_permission(self, request, view):
        """
        Check the permissions on the view.
        """

        permissions = self.get_permissions(view)

        if not permissions:
            return False

        return self.check_permissions(permissions, request, view, self.is_complex(permissions))

    def has_object_permission(self, request, view, obj):
        """
        Check the object permissions on the view.
        """

        permissions = self.get_permissions(view)

        if not permissions:
            return False

        for perm_class in permissions:
            if hasattr(perm_class, "__iter__"):
                classes = perm_class

                for perm_class in classes:
                    permission = perm_class()

                    if permission.has_object_permission(request, view, obj):
                        break
                    else:
                        return False
            else:
                permission = perm_class()

                if permission.has_object_permission(request, view, obj):
                    return True

        return False
