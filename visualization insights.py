import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Load your dataset
df = pd.read_csv(r"C:\Users\Linghesh\Desktop\Linghesh\CoLLege\Data Visualization Using Python\Mini Project\Network Intrusion Detection\Train_data.csv")

# Set up the plotting style
# Calculate the ratio of failed to successful logins
df['failed_to_successful_ratio'] = df['num_failed_logins'] / (df['logged_in'] + 1)  # add 1 to avoid division by zero

# Density plot to visualize the distribution of the failed-to-successful ratio for each class
plt.figure(figsize=(10, 6))
sns.kdeplot(data=df, x='failed_to_successful_ratio', hue='class', fill=True, common_norm=False, palette="mako")
plt.title("Density Plot of Failed to Successful Login Ratio by Class")
plt.xlabel("Failed to Successful Login Ratio")
plt.ylabel("Density")
plt.show()



failed_logins_counts = df.groupby(['class', 'num_failed_logins']).size().unstack(fill_value=0)

# Plot a stacked bar plot
failed_logins_counts.T.plot(kind='bar', stacked=True, figsize=(12, 8), colormap="viridis")
plt.title("Stacked Bar Plot of Failed Logins by Class")
plt.xlabel("Number of Failed Logins")
plt.ylabel("Frequency")
plt.legend(title="Class")
plt.xticks(rotation=0)
plt.show()
# Visualization 1: Class Distribution
plt.figure(figsize=(8, 6))
sns.countplot(x='class', data=df, palette='viridis')
plt.title("Distribution of Attack Classes")
plt.xlabel("Class")
plt.ylabel("Count")
plt.show()

# Visualization 2: Protocol Types and Anomaly
plt.figure(figsize=(10, 6))
sns.countplot(x='protocol_type', hue='class', data=df, palette='magma')
plt.title("Protocol Types by Class")
plt.xlabel("Protocol Type")
plt.ylabel("Count")
plt.show()

# Visualization 3: Service Types by Class
plt.figure(figsize=(12, 8))
sns.countplot(x='service', hue='class', data=df, palette='Set3')
plt.title("Service Types in Anomalies vs. Normals")
plt.xlabel("Service")
plt.ylabel("Count")
plt.xticks(rotation=90)
plt.show()

# Visualization 4: Flag Distribution in Anomalies vs. Normals
plt.figure(figsize=(10, 6))
sns.countplot(x='flag', hue='class', data=df, palette='coolwarm')
plt.title("Flag Distribution by Class")
plt.xlabel("Flag")
plt.ylabel("Count")
plt.show()

# Visualization 5: Source Bytes by Class
plt.figure(figsize=(8, 6))
sns.boxplot(x='class', y='src_bytes', data=df, palette="Blues")
plt.title("Source Bytes by Class")
plt.xlabel("Class")
plt.ylabel("Source Bytes")
plt.show()

# Visualization 6: Destination Bytes by Class
plt.figure(figsize=(8, 6))
sns.boxplot(x='class', y='dst_bytes', data=df, palette="Greens")
plt.title("Destination Bytes by Class")
plt.xlabel("Class")
plt.ylabel("Destination Bytes")
plt.show()

# Visualization 7: Failed Logins in Anomalies
plt.figure(figsize=(10, 6))
sns.histplot(df[df['class'] == 'anomaly']['num_failed_logins'], bins=20, kde=True, color="salmon")
plt.title("Failed Login Attempts in Anomalies")
plt.xlabel("Number of Failed Logins")
plt.ylabel("Frequency")
plt.show()

# Visualization 8: Same Service Rate by Class
plt.figure(figsize=(10, 6))
sns.kdeplot(data=df, x="same_srv_rate", hue="class", fill=True, common_norm=False, palette="viridis")
plt.title("Same Service Rate by Class")
plt.xlabel("Same Service Rate")
plt.ylabel("Density")
plt.show()

# Visualization 9: Service Error Rates by Class
plt.figure(figsize=(10, 6))
sns.violinplot(x="class", y="serror_rate", data=df, palette="muted")
plt.title("Service Error Rate by Class")
plt.xlabel("Class")
plt.ylabel("Service Error Rate")
plt.show()

# Additional Error Rates
plt.figure(figsize=(10, 6))
sns.violinplot(x="class", y="rerror_rate", data=df, palette="pastel")
plt.title("Remote Error Rate by Class")
plt.xlabel("Class")
plt.ylabel("Remote Error Rate")
plt.show()

# Visualization 10: Connection Duration by Class
plt.figure(figsize=(10, 6))
sns.boxplot(x='class', y='duration', data=df, palette="cividis")
plt.title("Connection Duration by Class")
plt.xlabel("Class")
plt.ylabel("Duration")
plt.show()

import matplotlib.pyplot as plt
import seaborn as sns

# Variables to visualize
rare_event_vars = ["wrong_fragment", "urgent", "land", "num_failed_logins"]

# Create subplots for rare event variables
fig, axes = plt.subplots(2, 2, figsize=(12, 10))
axes = axes.flatten()

for i, var in enumerate(rare_event_vars):
    sns.countplot(data=df, x=var, hue="class", ax=axes[i], palette="Set2")
    axes[i].set_title(f'Distribution of {var} by Class')
    axes[i].set_xlabel(var)
    axes[i].set_ylabel('Count')

plt.tight_layout()
plt.show()

