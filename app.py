# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

#!/usr/bin/env python3
import os

import aws_cdk as cdk
import cdk_nag

from aws_cdk import Aspects
from cdk.pjwt_with_pkce_stack import PjwtWithPkceStack


app = cdk.App()

Aspects.of(app).add(cdk_nag.AwsSolutionsChecks())

stack_name = app.node.try_get_context("stack_name")

PjwtWithPkceStack(app, stack_name)


app.synth()
