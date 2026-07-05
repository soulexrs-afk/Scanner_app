package com.example.scanner;

import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.List;

public class FindingAdapter extends RecyclerView.Adapter<FindingAdapter.ViewHolder> {

    private final List<Finding> findings;

    public FindingAdapter(List<Finding> findings) {
        this.findings = findings;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_finding, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        Finding f = findings.get(position);
        holder.title.setText(f.title);
        holder.detail.setText(f.detail);

        switch (f.severity) {
            case CRITICAL:
                holder.severityBadge.setText("CRITICAL");
                holder.severityBadge.setBackgroundColor(Color.parseColor("#D32F2F"));
                break;
            case WARNING:
                holder.severityBadge.setText("WARNING");
                holder.severityBadge.setBackgroundColor(Color.parseColor("#F57C00"));
                break;
            default:
                holder.severityBadge.setText("INFO");
                holder.severityBadge.setBackgroundColor(Color.parseColor("#388E3C"));
        }

        if (f.remediationSteps != null) {
            holder.remediation.setVisibility(View.VISIBLE);
            holder.remediation.setText("How to fix: " + f.remediationSteps);
        } else {
            holder.remediation.setVisibility(View.GONE);
        }
    }

    @Override
    public int getItemCount() {
        return findings.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView title, detail, remediation, severityBadge;

        ViewHolder(View itemView) {
            super(itemView);
            title = itemView.findViewById(R.id.findingTitle);
            detail = itemView.findViewById(R.id.findingDetail);
            remediation = itemView.findViewById(R.id.findingRemediation);
            severityBadge = itemView.findViewById(R.id.severityBadge);
        }
    }
}
