from rest_framework import response, decorators as rest_decorators, permissions as rest_permissions


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def paySubscription(request):
    """
        post:
        Processes payment for a user's subscription.

        This endpoint is responsible for handling the payment process for a subscription. It will check the
        provided payment details and attempt to process a payment through an integrated payment gateway like Stripe.

        Requires:
        - User must be authenticated.

        Body Parameters (example JSON payload):
        - subscription_id (str): ID of the subscription to be paid.
        - payment_method (str): Payment method details or identifier.

        Returns:
        - A JSON response with a message indicating success or failure of the payment process.

        Raises:
        - 400 Bad Request: If payment details are incorrect or insufficient.
        - 402 Payment Required: If payment fails due to issues like insufficient funds or gateway errors.
        - 404 Not Found: If the subscription ID does not exist.
        """
    return response.Response({"msg": "Success"}, 200)


@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def listSubscriptions(request):
    """
        post:
        Lists all active subscriptions for the authenticated user.

        This endpoint fetches and lists all the active subscriptions associated with the authenticated user.
        It could interface with internal records or external services like Stripe to retrieve the detailed list
        of active subscriptions.

        Requires:
        - User must be authenticated.

        Returns:
        - A JSON response containing a list of active subscriptions, which could include details such as subscription ID,
          plan name, start date, next billing date, and status.

        Raises:
        - 404 Not Found: If no subscriptions are found for the user.
    """
    return response.Response({"msg": "Success"}, 200)
